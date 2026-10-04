use crate::{Error, RequestOptions};
use bytes::Bytes;
use core::convert::Infallible;
use core::future::poll_fn;
use core::pin::{Pin, pin};
use core::task::{Poll, ready};
use http::header::{HeaderName, HeaderValue};
use http::uri::Scheme;
use http::{Request, Response};
use http_acl::HttpAcl;
use http_acl::mutation::{RequestMutation, ResponseMutation};
use http_acl::utils::authority::{Authority, Host};
use http_body::Body;
use http_body_util::{BodyExt, Full};
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

trait TokioStream: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {
    fn boxed(self) -> Box<dyn TokioStream>
    where
        Self: Sized,
    {
        Box::new(self)
    }
}
impl<T> TokioStream for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {}

/// Resolves `authority` (a `host:port` string), checking the host and each
/// candidate address against `acl` before connecting, and connects to
/// whichever resolved address succeeds first.
///
/// A trusted static DNS mapping (see
/// [`add_trusted_static_dns_mapping`](http_acl::HttpAclBuilder::add_trusted_static_dns_mapping))
/// bypasses the IP/port checks entirely, on the assumption that the embedder
/// vouches for that destination; a regular static mapping (or a genuinely
/// resolved address) is checked like any other candidate address.
async fn connect_with_acl(
    authority: &str,
    connect_timeout: Duration,
    acl: &HttpAcl,
) -> Result<TcpStream, Error> {
    let authority_parsed = Authority::parse(authority).map_err(|_| Error::HttpRequestUriInvalid)?;
    let port = authority_parsed.port;

    // Only ever `true` for a *trusted* static mapping: a regular static
    // mapping still needs its one address checked below, same as any
    // genuinely resolved address.
    let mut trusted_static_mapping = false;

    let tcp_addresses: Vec<SocketAddr> = match &authority_parsed.host {
        Host::Domain(domain) => {
            if let Some(tcp_address) = acl.resolve_trusted_static_dns_mapping(domain) {
                trusted_static_mapping = true;
                vec![tcp_address]
            } else if let Some(tcp_address) = acl.resolve_static_dns_mapping(domain) {
                vec![tcp_address]
            } else {
                let acl_host_match = acl.is_host_allowed(domain);
                if acl_host_match.is_denied() {
                    tracing::warn!("host {domain} is not allowed - {acl_host_match}");
                    return Err(Error::HttpRequestDenied);
                }

                match tokio::time::timeout(
                    connect_timeout,
                    tokio::net::lookup_host((domain.as_str(), port)),
                )
                .await
                {
                    Ok(Ok(addrs)) => addrs.collect(),
                    Ok(Err(e)) => {
                        tracing::warn!("dns lookup error: {e:?}");
                        return Err(Error::DnsError {
                            rcode: None,
                            info_code: None,
                        });
                    }
                    Err(..) => return Err(Error::DnsTimeout),
                }
            }
        }
        Host::Ip(ip) => {
            let acl_ip_match = acl.is_ip_allowed(ip);
            if acl_ip_match.is_denied() {
                tracing::warn!("IP {ip} is not allowed - {acl_ip_match}");
                return Err(Error::DestinationIpProhibited);
            }
            vec![SocketAddr::new(*ip, port)]
        }
    };

    if tcp_addresses.is_empty() {
        return Err(Error::DnsError {
            rcode: None,
            info_code: None,
        });
    }

    if !trusted_static_mapping {
        for tcp_address in &tcp_addresses {
            let acl_ip_match = acl.is_ip_allowed(&tcp_address.ip());
            if acl_ip_match.is_denied() {
                tracing::warn!("IP {} is not allowed - {}", tcp_address.ip(), acl_ip_match);
                return Err(Error::DestinationIpProhibited);
            }
        }
    }

    match tokio::time::timeout(
        connect_timeout,
        TcpStream::connect(tcp_addresses.as_slice()),
    )
    .await
    {
        Ok(stream) => stream.map_err(Error::Connect),
        Err(..) => Err(Error::ConnectionTimeout),
    }
}

/// The default implementation of how an outgoing request is sent.
///
/// This implementation is used by the `wasi:http/handler` interface
/// default implementation.
///
/// The returned [Future] can be used to communicate
/// a request processing error, if any, to the constructor of the request.
/// For example, if the request was constructed via `wasi:http/types.request#new`,
/// a result resolved from it will be forwarded to the guest on the future handle returned.
///
/// This function performs no `Content-Length` validation.
pub async fn default_send_request(
    req: Request<impl Body<Data = Bytes, Error = Error> + Send + 'static>,
    options: Option<RequestOptions>,
) -> Result<
    (
        Response<impl Body<Data = Bytes, Error = Error>>,
        impl Future<Output = Result<(), Error>> + Send,
    ),
    Error,
> {
    let uri = req.uri();
    let authority = uri.authority().ok_or(Error::HttpRequestUriInvalid)?;
    let use_tls = uri.scheme() == Some(&Scheme::HTTPS);
    let authority = if authority.port().is_some() {
        authority.to_string()
    } else {
        let port = if use_tls { 443 } else { 80 };
        format!("{authority}:{port}")
    };

    let connect_timeout = options
        .as_ref()
        .and_then(|r| r.connect_timeout)
        .unwrap_or(Duration::from_secs(600));

    let first_byte_timeout = options
        .as_ref()
        .and_then(|r| r.first_byte_timeout)
        .unwrap_or(Duration::from_secs(600));

    let between_bytes_timeout = options
        .as_ref()
        .and_then(|r| r.between_bytes_timeout)
        .unwrap_or(Duration::from_secs(600));

    // An ACL attached by `crate::p2::http_impl`/`crate::p3::host::handler` (via
    // `RequestOptions::acl`) is checked here; a caller going through neither
    // (e.g. calling this function directly) gets the same unrestricted
    // behavior Wasmtime always had before ACL enforcement was added.
    let acl = options
        .and_then(|r| r.acl)
        .unwrap_or_else(|| std::sync::Arc::new(crate::ctx::permissive_acl()));

    let scheme_str = if use_tls { "https" } else { "http" };
    let authority_for_hooks =
        Authority::parse(&authority).map_err(|_| Error::HttpRequestUriInvalid)?;

    // Boxed unconditionally (cheap - not a buffer) so both branches below produce
    // the same concrete body type; the request body is only ever actually read
    // into memory when a `ModifyRequestFn` is attached.
    let mut req: Request<http_body_util::combinators::UnsyncBoxBody<Bytes, Error>> = if acl
        .has_modify_request()
    {
        let (mut parts, body) = req.into_parts();
        let body_bytes = body.collect().await?.to_bytes();
        let mut mutation = RequestMutation {
            headers: parts
                .headers
                .iter()
                .map(|(k, v)| {
                    (
                        k.as_str().to_string(),
                        String::from_utf8_lossy(v.as_bytes()).into_owned(),
                    )
                })
                .collect(),
            body: Some(body_bytes),
        };
        acl.modify_request(scheme_str, &authority_for_hooks, &mut mutation);

        parts.headers.clear();
        for (name, value) in &mutation.headers {
            let header_name = HeaderName::from_str(name)
                .map_err(|_| Error::InternalError(Some(format!("invalid header name `{name}`"))))?;
            let header_value = HeaderValue::from_str(value).map_err(|_| {
                Error::InternalError(Some(format!("invalid header value for `{name}`")))
            })?;
            parts.headers.append(header_name, header_value);
        }
        Request::from_parts(
            parts,
            Full::new(mutation.body.unwrap_or_default())
                .map_err(|infallible: Infallible| match infallible {})
                .boxed_unsync(),
        )
    } else {
        req.map(BodyExt::boxed_unsync)
    };

    let stream = connect_with_acl(&authority, connect_timeout, &acl).await?;
    let stream = if use_tls {
        // derived from https://github.com/rustls/rustls/blob/main/examples/src/bin/simpleclient.rs
        let root_cert_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.into(),
        };
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
        let domain = tls_server_name(&authority)?;
        let stream = connector
            .connect(domain, stream)
            .await
            .map_err(Error::Tls)?;
        stream.boxed()
    } else {
        stream.boxed()
    };
    let (mut sender, conn) = tokio::time::timeout(
        connect_timeout,
        // TODO: we should plumb the builder through the http context, and use it here
        hyper::client::conn::http1::Builder::new().handshake(crate::io::TokioIo::new(stream)),
    )
    .await
    .map_err(|_| Error::ConnectionTimeout)??;

    // at this point, the request contains the scheme and the authority, but
    // the http packet should only include those if addressing a proxy, so
    // remove them here, since SendRequest::send_request does not do it for us
    *req.uri_mut() = http::Uri::builder()
        .path_and_query(
            req.uri()
                .path_and_query()
                .map(|p| p.as_str())
                .unwrap_or("/"),
        )
        .build()
        .expect("comes from valid request");

    let send = async move {
        use core::task::Context;

        /// Wrapper around [hyper::body::Incoming] used to
        /// account for request option timeout configuration
        struct IncomingResponseBody {
            incoming: hyper::body::Incoming,
            timeout: tokio::time::Interval,
        }
        impl http_body::Body for IncomingResponseBody {
            type Data = <hyper::body::Incoming as http_body::Body>::Data;
            type Error = Error;

            fn poll_frame(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
                match Pin::new(&mut self.as_mut().incoming).poll_frame(cx) {
                    Poll::Ready(None) => Poll::Ready(None),
                    Poll::Ready(Some(Err(err))) => {
                        let err = if err.is_timeout() {
                            Error::HttpResponseTimeout
                        } else {
                            Error::from(err)
                        };
                        Poll::Ready(Some(Err(err)))
                    }
                    Poll::Ready(Some(Ok(frame))) => {
                        self.timeout.reset();
                        Poll::Ready(Some(Ok(frame)))
                    }
                    Poll::Pending => {
                        ready!(self.timeout.poll_tick(cx));
                        Poll::Ready(Some(Err(Error::ConnectionReadTimeout)))
                    }
                }
            }
            fn is_end_stream(&self) -> bool {
                self.incoming.is_end_stream()
            }
            fn size_hint(&self) -> http_body::SizeHint {
                self.incoming.size_hint()
            }
        }

        let res = tokio::time::timeout(first_byte_timeout, sender.send_request(req))
            .await
            .map_err(|_| Error::ConnectionReadTimeout)?
            .map_err(Error::from)?;
        // Tokio panics on an `interval` with a zero duration, so clamp it to a
        // 1ns timeout which is sort of effectively zero anyway.
        let between_bytes_timeout = if between_bytes_timeout == Duration::ZERO {
            Duration::new(0, 1)
        } else {
            between_bytes_timeout
        };
        let mut timeout = tokio::time::interval(between_bytes_timeout);
        timeout.reset();
        Ok(res.map(|incoming| IncomingResponseBody { incoming, timeout }))
    };
    let mut send = pin!(send);
    let mut conn = Some(conn);
    // Wait for response while driving connection I/O
    let res = poll_fn(|cx| match send.as_mut().poll(cx) {
        Poll::Ready(Ok(res)) => Poll::Ready(Ok(res)),
        Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        Poll::Pending => {
            // Response is not ready, poll `hyper` connection to drive I/O if it has not completed yet
            let Some(fut) = conn.as_mut() else {
                // `hyper` connection already completed
                return Poll::Pending;
            };
            let res = ready!(Pin::new(fut).poll(cx));
            // `hyper` connection completed, record that to prevent repeated poll
            conn = None;
            match res {
                // `hyper` connection has successfully completed, optimistically poll for response
                Ok(()) => send.as_mut().poll(cx),
                // `hyper` connection has failed, return the error
                Err(err) => Poll::Ready(Err(Error::from(err))),
            }
        }
    })
    .await?;

    // Boxed unconditionally (cheap - not a buffer) so both branches produce the
    // same concrete body type; the response body is only ever actually read into
    // memory when a `ModifyResponseFn` is attached, requiring the connection to be
    // driven concurrently the same way the header-wait `poll_fn` above does.
    let res: Response<http_body_util::combinators::UnsyncBoxBody<Bytes, Error>> = if acl
        .has_modify_response()
    {
        let (parts, body) = res.into_parts();
        let mut collect = pin!(body.collect());
        let collected = poll_fn(|cx| match collect.as_mut().poll(cx) {
            Poll::Ready(r) => Poll::Ready(r),
            Poll::Pending => {
                let Some(fut) = conn.as_mut() else {
                    return Poll::Pending;
                };
                let res = ready!(Pin::new(fut).poll(cx));
                conn = None;
                match res {
                    Ok(()) => collect.as_mut().poll(cx),
                    Err(err) => Poll::Ready(Err(Error::from(err))),
                }
            }
        })
        .await?;

        let mut mutation = ResponseMutation {
            status: parts.status.as_u16(),
            headers: parts
                .headers
                .iter()
                .map(|(k, v)| {
                    (
                        k.as_str().to_string(),
                        String::from_utf8_lossy(v.as_bytes()).into_owned(),
                    )
                })
                .collect(),
            body: collected.to_bytes(),
        };
        acl.modify_response(scheme_str, &authority_for_hooks, &mut mutation);

        let mut new_parts = parts;
        new_parts.status = http::StatusCode::from_u16(mutation.status).map_err(|_| {
            Error::InternalError(Some(format!("invalid status code {}", mutation.status)))
        })?;
        new_parts.headers.clear();
        for (name, value) in &mutation.headers {
            let header_name = HeaderName::from_str(name)
                .map_err(|_| Error::InternalError(Some(format!("invalid header name `{name}`"))))?;
            let header_value = HeaderValue::from_str(value).map_err(|_| {
                Error::InternalError(Some(format!("invalid header value for `{name}`")))
            })?;
            new_parts.headers.append(header_name, header_value);
        }
        Response::from_parts(
            new_parts,
            Full::new(mutation.body)
                .map_err(|infallible: Infallible| match infallible {})
                .boxed_unsync(),
        )
    } else {
        res.map(BodyExt::boxed_unsync)
    };

    Ok((res, async move {
        let Some(conn) = conn.take() else {
            // `hyper` connection has already completed
            return Ok(());
        };
        if let Err(err) = conn.await {
            if err.is_timeout() {
                return Err(Error::HttpResponseTimeout);
            }
            return Err(err.into());
        }
        Ok(())
    }))
}

/// Resolve the rustls [`ServerName`] used for TLS certificate verification from
/// an outbound request `authority`.
///
/// `authority` is in `host:port` form, where an IPv6 `host` is wrapped in
/// brackets (for example `[::1]:443`). An IP literal is recognized by parsing
/// the whole authority as a [`SocketAddr`]; this handles the bracketed IPv6
/// form, which splitting on the first `:` would truncate. Anything else is
/// treated as a host name, with the port stripped off before it is handed to
/// rustls.
///
/// [`ServerName`]: rustls::pki_types::ServerName
/// [`SocketAddr`]: std::net::SocketAddr
pub(crate) fn tls_server_name(
    authority: &str,
) -> Result<rustls::pki_types::ServerName<'static>, rustls::pki_types::InvalidDnsNameError> {
    use rustls::pki_types::ServerName;

    if let Ok(addr) = authority.parse::<std::net::SocketAddr>() {
        return Ok(ServerName::from(addr.ip()));
    }
    let host = match authority.split_once(':') {
        Some((host, _port)) => host,
        None => authority,
    };
    Ok(ServerName::try_from(host)?.to_owned())
}

#[cfg(test)]
mod tls_server_name_tests {
    use super::tls_server_name;
    use rustls::pki_types::ServerName;

    #[test]
    fn resolves_server_name_from_authority() {
        // Host names keep their host and drop the port.
        assert_eq!(
            tls_server_name("example.com:443").unwrap(),
            ServerName::try_from("example.com").unwrap()
        );
        assert_eq!(
            tls_server_name("example.com").unwrap(),
            ServerName::try_from("example.com").unwrap()
        );

        // IP literals resolve to an `IpAddress` server name. The bracketed IPv6
        // form must not be truncated at the first `:`.
        assert_eq!(
            tls_server_name("127.0.0.1:80").unwrap(),
            ServerName::from(std::net::Ipv4Addr::LOCALHOST)
        );
        assert_eq!(
            tls_server_name("[::1]:443").unwrap(),
            ServerName::from(std::net::Ipv6Addr::LOCALHOST)
        );
        assert_eq!(
            tls_server_name("[2001:db8::1]:8443").unwrap(),
            ServerName::from("2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap())
        );
    }
}

/// Exercises `modify_request`/`modify_response` directly against
/// [`default_send_request`], the function shared by both the p2 and p3 outbound
/// send paths - proving the buffering/rebuild logic (including the `poll_fn`
/// combinator that drives the `hyper` connection concurrently with collecting a
/// response body) against a real TCP connection, independent of either WASI HTTP
/// version's own plumbing (already covered separately by the p2 integration test).
#[cfg(test)]
mod modify_hooks_tests {
    use super::default_send_request;
    use crate::RequestOptions;
    use bytes::Bytes;
    use core::convert::Infallible;
    use http::Request;
    use http_acl::{HttpAcl, HttpAclHooks};
    use http_body_util::{BodyExt, Full};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn modify_request_and_response_hooks_are_applied() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (captured_tx, captured_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let _ = captured_tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
                let body = "original body";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nx-remove-me: yes\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let acl = HttpAcl::builder()
            .non_global_ip_ranges(true)
            .ip_acl_default(true)
            .port_acl_default(true)
            .host_acl_default(true)
            .build_full(HttpAclHooks {
                modify_request_fn: Some(Arc::new(|_scheme, _authority, mutation| {
                    mutation
                        .headers
                        .push(("x-injected-secret".to_string(), "sssh".to_string()));
                })),
                modify_response_fn: Some(Arc::new(|_scheme, _authority, mutation| {
                    mutation.status = 201;
                    mutation.headers.retain(|(k, _)| k != "x-remove-me");
                    mutation.body = Bytes::from_static(b"redacted body");
                })),
                ..Default::default()
            });

        let req = Request::builder()
            .method("GET")
            .uri(format!("http://127.0.0.1:{}/", addr.port()))
            .body(
                Full::new(Bytes::new())
                    .map_err(|infallible: Infallible| match infallible {})
                    .boxed_unsync(),
            )
            .unwrap();

        let (res, io) = default_send_request(
            req,
            Some(RequestOptions {
                acl: Some(Arc::new(acl)),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        assert_eq!(res.status(), 201);
        assert!(!res.headers().contains_key("x-remove-me"));
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"redacted body");

        io.await.unwrap();

        let captured = captured_rx.await.unwrap();
        assert!(
            captured.to_lowercase().contains("x-injected-secret: sssh"),
            "captured request did not contain the injected header:\n{captured}"
        );
    }

    #[tokio::test]
    async fn no_hooks_configured_is_unaffected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let acl = HttpAcl::builder()
            .non_global_ip_ranges(true)
            .ip_acl_default(true)
            .port_acl_default(true)
            .host_acl_default(true)
            .build();
        assert!(!acl.has_modify_request());
        assert!(!acl.has_modify_response());

        let req = Request::builder()
            .method("GET")
            .uri(format!("http://127.0.0.1:{}/", addr.port()))
            .body(
                Full::new(Bytes::new())
                    .map_err(|infallible: Infallible| match infallible {})
                    .boxed_unsync(),
            )
            .unwrap();

        let (res, io) = default_send_request(
            req,
            Some(RequestOptions {
                acl: Some(Arc::new(acl)),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        assert_eq!(res.status(), 200);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"ok");

        io.await.unwrap();
    }
}
