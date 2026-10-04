//! Implementation of the `wasi:http/outgoing-handler` interface.

use crate::WasiHttpCtxView;
use crate::p2::{
    HttpResult,
    bindings::http::{
        outgoing_handler,
        types::{self, Scheme},
    },
    error::internal_error,
    http_request_error,
    types::{HostFutureIncomingResponse, HostOutgoingRequest},
};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::Method;
use std::pin::Pin;
use wasmtime::component::Resource;

impl outgoing_handler::Host for WasiHttpCtxView<'_> {
    fn handle(
        &mut self,
        request_id: Resource<HostOutgoingRequest>,
        options: Option<Resource<types::RequestOptions>>,
    ) -> HttpResult<Resource<HostFutureIncomingResponse>> {
        let opts = options.and_then(|opts| self.table.get(&opts).ok()).cloned();

        let req = self.table.delete(request_id)?;
        let mut builder = hyper::Request::builder();

        let acl = self.ctx.acl.clone();

        let method_str = match &req.method {
            types::Method::Get => "GET",
            types::Method::Head => "HEAD",
            types::Method::Post => "POST",
            types::Method::Put => "PUT",
            types::Method::Delete => "DELETE",
            types::Method::Connect => "CONNECT",
            types::Method::Options => "OPTIONS",
            types::Method::Trace => "TRACE",
            types::Method::Patch => "PATCH",
            types::Method::Other(m) => m.as_str(),
        };
        let acl_method_match = acl.is_method_allowed(method_str);
        if acl_method_match.is_denied() {
            return Err(internal_error(format!(
                "Method {method_str} is not allowed - {acl_method_match}",
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

        let scheme = match req.scheme {
            Some(scheme) => {
                let scheme = match scheme {
                    Scheme::Http => http::uri::Scheme::HTTP,
                    Scheme::Https => http::uri::Scheme::HTTPS,
                    Scheme::Other(scheme) => http::uri::Scheme::try_from(scheme.as_str())
                        .map_err(|_| types::ErrorCode::HttpProtocolError)?,
                };
                if !self.hooks.is_supported_scheme(&scheme) {
                    return Err(types::ErrorCode::HttpProtocolError.into());
                }
                scheme
            }
            // Note that a hook returning `None` here means that guests are
            // required to specify a scheme themselves.
            None => self
                .hooks
                .default_scheme()
                .ok_or(types::ErrorCode::HttpProtocolError)?,
        };

        let acl_scheme_match = acl.is_scheme_allowed(scheme.as_str());
        if acl_scheme_match.is_denied() {
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
            return Err(
                internal_error(format!("Port {port} is not allowed - {acl_port_match}")).into(),
            );
        }

        let mut uri = http::Uri::builder()
            .scheme(scheme)
            .authority(authority.clone());

        if let Some(path) = req.path_with_query {
            if let Some(url_path) = path.split('?').next() {
                let acl_url_path_match = acl.is_url_path_allowed(url_path);
                if acl_url_path_match.is_denied() {
                    return Err(internal_error(format!(
                        "URL Path {url_path} is not allowed - {acl_url_path_match}"
                    ))
                    .into());
                }
            }

            uri = uri.path_and_query(path);
        }

        builder = builder.uri(uri.build().map_err(http_request_error)?);

        if self.hooks.set_host_header() {
            builder = builder.header(http::header::HOST, authority.as_str());
        }

        for (k, v) in req.headers.iter() {
            builder = builder.header(k, v);
        }

        let body = req.body.unwrap_or_else(|| {
            Empty::<Bytes>::new()
                .map_err(|_| unreachable!("Infallible error"))
                .boxed_unsync()
        });
        let body = body.map_err(Into::into).boxed_unsync();

        let request = builder
            .body(body)
            .map_err(|err| internal_error(err.to_string()))?;

        let mut opts = opts.unwrap_or_default();
        opts.acl = Some(acl);

        let future = self
            .hooks
            .send_request(request, Some(opts), Box::new(async { Ok(()) }));
        let future = wasmtime_wasi::runtime::spawn(async move {
            let (res, io) = Pin::from(future).await?;
            let io = wasmtime_wasi::runtime::spawn(async move {
                match Pin::from(io).await {
                    Ok(()) => {}
                    // TODO: shouldn't throw away this error and ideally should
                    // surface somewhere.
                    Err(e) => tracing::warn!("dropping error {e}"),
                }
            });
            let res = res.map(|b| b.boxed_unsync());
            Ok((res, io))
        });

        Ok(self
            .table
            .push(HostFutureIncomingResponse::Pending(future))?)
    }
}
