//! Implementation of the `wasi:http/outgoing-handler` interface.

use crate::{
    WasiHttpImpl, WasiHttpView,
    bindings::http::{
        outgoing_handler,
        types::{self, Scheme},
    },
    error::internal_error,
    http_request_error,
    types::{HostFutureIncomingResponse, HostOutgoingRequest, OutgoingRequestConfig},
};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::Method;
use wasmtime::component::Resource;

impl<T> outgoing_handler::Host for WasiHttpImpl<T>
where
    T: WasiHttpView,
{
    fn handle(
        &mut self,
        request_id: Resource<HostOutgoingRequest>,
        options: Option<Resource<types::RequestOptions>>,
    ) -> crate::HttpResult<Resource<HostFutureIncomingResponse>> {
        let opts = options.and_then(|opts| self.table().get(&opts).ok());

        let connect_timeout = opts
            .and_then(|opts| opts.connect_timeout)
            .unwrap_or(std::time::Duration::from_secs(600));

        let first_byte_timeout = opts
            .and_then(|opts| opts.first_byte_timeout)
            .unwrap_or(std::time::Duration::from_secs(600));

        let between_bytes_timeout = opts
            .and_then(|opts| opts.between_bytes_timeout)
            .unwrap_or(std::time::Duration::from_secs(600));

        let req = self.table().delete(request_id)?;
        let mut builder = hyper::Request::builder();

        let acl = self.ctx().acl.clone();

        let method = match req.method {
            types::Method::Get => "GET",
            types::Method::Head => "HEAD",
            types::Method::Post => "POST",
            types::Method::Put => "PUT",
            types::Method::Delete => "DELETE",
            types::Method::Connect => "CONNECT",
            types::Method::Options => "OPTIONS",
            types::Method::Trace => "TRACE",
            types::Method::Patch => "PATCH",
            types::Method::Other(ref m) => m,
        };

        let acl_method_match = acl.is_method_allowed(method);
        if acl_method_match.is_denied() {
            self.acl_denied("method", &acl_host(req.authority.as_deref()));
            return Err(internal_error(format!(
                "Method {method} is not allowed - {acl_method_match}",
            ))
            .into());
        }

        builder = builder.method(match req.method {
            types::Method::Get => Method::GET,
            types::Method::Head => Method::HEAD,
            types::Method::Post => Method::POST,
            types::Method::Put => Method::PUT,
            types::Method::Delete => Method::DELETE,
            types::Method::Connect => Method::CONNECT,
            types::Method::Options => Method::OPTIONS,
            types::Method::Trace => Method::TRACE,
            types::Method::Patch => Method::PATCH,
            types::Method::Other(m) => match hyper::Method::from_bytes(m.as_bytes()) {
                Ok(method) => method,
                Err(_) => return Err(types::ErrorCode::HttpRequestMethodInvalid.into()),
            },
        });

        let (use_tls, scheme) = match req.scheme.unwrap_or(Scheme::Https) {
            Scheme::Http => (false, http::uri::Scheme::HTTP),
            Scheme::Https => (true, http::uri::Scheme::HTTPS),

            // We can only support http/https
            Scheme::Other(_) => return Err(types::ErrorCode::HttpProtocolError.into()),
        };

        let acl_scheme_match = acl.is_scheme_allowed(scheme.as_str());
        if acl_scheme_match.is_denied() {
            self.acl_denied("scheme", &acl_host(req.authority.as_deref()));
            return Err(internal_error(format!(
                "Scheme {scheme} is not allowed - {acl_scheme_match}"
            ))
            .into());
        }

        let authority = req.authority.unwrap_or_else(String::new);

        let authority_parsed = match http_acl::utils::authority::Authority::parse(&authority) {
            Ok(a) => a,
            Err(e) => return Err(internal_error(format!("invalid authority: {e}")).into()),
        };
        let port = if authority_parsed.port == 0 {
            match scheme.as_str() {
                "http" => 80,
                "https" => 443,
                _ => unreachable!(),
            }
        } else {
            authority_parsed.port
        };
        let acl_port_match = acl.is_port_allowed(port);
        if acl_port_match.is_denied() {
            self.acl_denied("port", &authority_parsed.host.to_string());
            return Err(
                internal_error(format!("Port {port} is not allowed - {acl_port_match}")).into(),
            );
        }

        builder = builder.header(hyper::header::HOST, &authority);

        let mut uri = http::Uri::builder()
            .scheme(scheme)
            .authority(authority.clone());

        // The ACL sees the path the way the server will: percent-decoded, with dot
        // segments resolved (http-acl 0.12 does the same in its reqwest middleware).
        // Matching the raw path let `/%61dmin` or `/x/../admin` past a denied `/admin`.
        // A request without a path is sent to `/`, so `/` is what is checked.
        let raw_path = req.path_with_query.as_deref().unwrap_or("/");
        let raw_path = raw_path.split(['?', '#']).next().unwrap_or("");
        let separator = if raw_path.starts_with('/') { "" } else { "/" };
        let Some(url_path) = http_acl::utils::url::get_url_path(&format!(
            "http://acl.invalid{separator}{raw_path}"
        )) else {
            self.acl_denied("path", &authority_parsed.host.to_string());
            return Err(internal_error(format!(
                "URL Path {raw_path} is not allowed - invalid path"
            ))
            .into());
        };
        let acl_url_path_match = acl.is_url_path_allowed(&url_path);
        if acl_url_path_match.is_denied() {
            self.acl_denied("path", &authority_parsed.host.to_string());
            return Err(internal_error(format!(
                "URL Path {url_path} is not allowed - {acl_url_path_match}"
            ))
            .into());
        }

        if let Some(path) = req.path_with_query {
            uri = uri.path_and_query(path);
        }

        builder = builder.uri(uri.build().map_err(http_request_error)?);

        for (k, v) in req.headers.as_ref().iter() {
            builder = builder.header(k, v);
        }

        let body = req.body.unwrap_or_else(|| {
            Empty::<Bytes>::new()
                .map_err(|_| unreachable!("Infallible error"))
                .boxed()
        });

        let request = builder
            .body(body)
            .map_err(|err| internal_error(err.to_string()))?;

        let future = self.send_request(
            request,
            OutgoingRequestConfig {
                use_tls,
                connect_timeout,
                first_byte_timeout,
                between_bytes_timeout,
                acl,
                authority: authority_parsed,
            },
        )?;

        Ok(self.table().push(future)?)
    }
}

/// The host part of a request's authority, for [`WasiHttpView::acl_denied`] on a denial found
/// before the authority is parsed; empty when there is none or it does not parse.
fn acl_host(authority: Option<&str>) -> String {
    authority
        .and_then(|a| http_acl::utils::authority::Authority::parse(a).ok())
        .map(|a| a.host.to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        WasiHttpCtx,
        types::{FieldMap, HostFutureIncomingResponse, OutgoingRequestConfig},
    };
    use http_acl::HttpAcl;
    use wasmtime::component::ResourceTable;

    /// A view that records each ACL denial the fork reports, and each request that got as far
    /// as `send_request`.
    struct Recorder {
        ctx: WasiHttpCtx,
        table: ResourceTable,
        denials: Vec<(&'static str, String)>,
        sent: usize,
    }

    impl WasiHttpView for Recorder {
        fn ctx(&mut self) -> &mut WasiHttpCtx {
            &mut self.ctx
        }

        fn table(&mut self) -> &mut ResourceTable {
            &mut self.table
        }

        fn send_request(
            &mut self,
            _request: hyper::Request<crate::body::HyperOutgoingBody>,
            _config: OutgoingRequestConfig,
        ) -> crate::HttpResult<HostFutureIncomingResponse> {
            self.sent += 1;
            Err(internal_error("not sent in this test".to_string()).into())
        }

        fn acl_denied(&mut self, reason: &'static str, host: &str) {
            self.denials.push((reason, host.to_string()));
        }
    }

    fn handle(
        acl: HttpAcl,
        method: types::Method,
        scheme: Scheme,
        authority: &str,
        path: &str,
    ) -> (Vec<(&'static str, String)>, usize) {
        let mut view = Recorder {
            ctx: WasiHttpCtx::new_with_acl(acl),
            table: ResourceTable::new(),
            denials: Vec::new(),
            sent: 0,
        };
        let request = view
            .table
            .push(HostOutgoingRequest {
                method,
                scheme: Some(scheme),
                authority: Some(authority.to_string()),
                path_with_query: Some(path.to_string()),
                headers: FieldMap::empty(usize::MAX),
                body: None,
            })
            .unwrap();
        let result = outgoing_handler::Host::handle(&mut WasiHttpImpl(&mut view), request, None);
        assert!(result.is_err());
        (view.denials, view.sent)
    }

    fn acl() -> http_acl::HttpAclBuilder {
        HttpAcl::builder()
            .ip_acl_default(true)
            .host_acl_default(true)
            .port_acl_default(true)
            .method_acl_default(true)
            .header_acl_default(true)
            .url_path_acl_default(true)
    }

    fn denial(reason: &'static str) -> Vec<(&'static str, String)> {
        vec![(reason, "example.com".to_string())]
    }

    #[test]
    fn denied_method_is_reported() {
        let acl = acl()
            .clear_allowed_methods()
            .add_denied_method("DELETE")
            .unwrap()
            .build();
        let got = handle(
            acl,
            types::Method::Delete,
            Scheme::Https,
            "example.com",
            "/",
        );
        assert_eq!(got, (denial("method"), 0));
    }

    #[test]
    fn denied_scheme_is_reported() {
        let acl = acl().http(false).build();
        let got = handle(acl, types::Method::Get, Scheme::Http, "example.com", "/");
        assert_eq!(got, (denial("scheme"), 0));
    }

    #[test]
    fn denied_port_is_reported() {
        let acl = acl().add_denied_port_range(8080..=8080).unwrap().build();
        let got = handle(
            acl,
            types::Method::Get,
            Scheme::Https,
            "example.com:8080",
            "/",
        );
        assert_eq!(got, (denial("port"), 0));
    }

    #[test]
    fn denied_path_is_reported() {
        let acl = acl()
            .add_denied_url_path("/admin".to_string())
            .unwrap()
            .build();
        let got = handle(
            acl,
            types::Method::Get,
            Scheme::Https,
            "example.com",
            "/%61dmin",
        );
        assert_eq!(got, (denial("path"), 0));
    }

    #[test]
    fn allowed_request_reports_nothing() {
        let got = handle(
            acl().build(),
            types::Method::Get,
            Scheme::Https,
            "example.com",
            "/",
        );
        assert_eq!(got, (Vec::new(), 1));
    }
}
