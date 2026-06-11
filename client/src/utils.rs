use bytes::Bytes;
use rig_core::{
    http_client::{self, LazyBody, Request, Response},
    wasm_compat::WasmCompatSend,
};
use std::io;

pub fn http_client_error(message: impl Into<String>) -> http_client::Error {
    http_client::Error::Instance(Box::new(io::Error::new(
        io::ErrorKind::InvalidData,
        message.into(),
    )))
}

pub fn encode_request<T>(req: Request<T>) -> Bytes
where
    T: Into<Bytes>,
{
    let (parts, body) = req.into_parts();
    let body = body.into();
    let path = parts
        .uri
        .path_and_query()
        .map(|path| path.as_str())
        .unwrap_or("/");

    let mut wire = Vec::new();
    wire.extend_from_slice(format!("{} {} HTTP/1.1\r\n", parts.method, path).as_bytes());

    if let Some(authority) = parts.uri.authority() {
        wire.extend_from_slice(format!("Host: {}\r\n", authority).as_bytes());
    }

    let mut has_content_length = false;
    let mut has_connection = false;
    for (name, value) in parts.headers.iter() {
        if name.as_str().eq_ignore_ascii_case("host") {
            continue;
        }
        if name.as_str().eq_ignore_ascii_case("content-length") {
            has_content_length = true;
        }
        if name.as_str().eq_ignore_ascii_case("connection") {
            has_connection = true;
        }

        wire.extend_from_slice(name.as_str().as_bytes());
        wire.extend_from_slice(b": ");
        wire.extend_from_slice(value.as_bytes());
        wire.extend_from_slice(b"\r\n");
    }

    if !has_content_length {
        wire.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    if !has_connection {
        wire.extend_from_slice(b"Connection: close\r\n");
    }

    wire.extend_from_slice(b"\r\n");
    wire.extend_from_slice(&body);

    Bytes::from(wire)
}

pub fn decode_response<U>(data: Vec<u8>) -> http_client::Result<Response<LazyBody<U>>>
where
    U: From<Bytes>,
    U: WasmCompatSend + 'static,
{
    let header_end = data
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| http_client_error("HTTP response missing header terminator"))?;
    let (head, body) = data.split_at(header_end + 4);
    let head = std::str::from_utf8(&head[..header_end])
        .map_err(|error| http_client_error(format!("invalid HTTP response headers: {error}")))?;

    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| http_client_error("HTTP response missing status line"))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| http_client_error("HTTP response missing status code"))?
        .parse::<u16>()
        .map_err(|error| http_client_error(format!("invalid HTTP response status: {error}")))?;

    let mut builder = Response::builder().status(status);
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            builder = builder.header(name.trim(), value.trim());
        }
    }

    let body = Bytes::copy_from_slice(body);
    let lazy_body: LazyBody<U> = Box::pin(async move { Ok(U::from(body)) });

    builder
        .body(lazy_body)
        .map_err(http_client::Error::Protocol)
}
