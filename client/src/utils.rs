use std::io;
use regex::bytes::Regex;
use bytes::Bytes;
use rig_core::{
    http_client::{self, LazyBody, Request, Response},
    wasm_compat::WasmCompatSend,
};

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

pub fn check_and_padding(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let target_body_len: usize = std::env::var("CONTENT_LENGTH")
        .map_err(|_| anyhow::anyhow!("CONTENT_LENGTH must be set"))?
        .parse()
        .map_err(|error| anyhow::anyhow!("invalid CONTENT_LENGTH: {error}"))?;

    let re = Regex::new(
        r#"(?is)POST\s+[^\r\n]+\r\nHost:\s*([^\r\n]*)\r\nauthorization:\s*Bearer\s+([^\r\n]+)\r\ncontent-type:\s*application/json\r\nContent-Length:\s*([^\r\n]*)\r\nConnection:\s*close\r\n\r\n\{.*?"model":"([^"]*)".*?"role":"system".*?"text":"([^"]*)".*?"role":"user".*?"content":"([^"]*)".*?\}"#,
    )
    .expect("Invalid regex pattern");
    if re.captures(data).is_none() {
        return Err(anyhow::anyhow!("failed to parse chat completion request"));
    }

    const SEP: &[u8] = b"\r\n\r\n";
    let sep_pos = data
        .windows(SEP.len())
        .position(|w| w == SEP)
        .ok_or_else(|| anyhow::anyhow!("HTTP request missing header/body separator"))?;
    let (headers, body) = (&data[..sep_pos], &data[sep_pos + SEP.len()..]);

    if body.len() == target_body_len {
        return Ok(data.to_vec());
    }
    if body.len() > target_body_len {
        return Err(anyhow::anyhow!(
            "request body length {} exceeds maximum {target_body_len}",
            body.len()
        ));
    }

    let pad_len = target_body_len - body.len();
    let text_re = Regex::new(r#"(?s)"role":"user","content":"((?:[^"\\]|\\.)*)""#)
        .expect("Invalid regex pattern");
    let caps = text_re
        .captures(body)
        .ok_or_else(|| anyhow::anyhow!("user content field not found"))?;
    let text = caps
        .get(1)
        .ok_or_else(|| anyhow::anyhow!("user content field not found"))?;
    let insert_pos = text.end();

    let mut new_body = Vec::with_capacity(target_body_len);
    new_body.extend_from_slice(&body[..insert_pos]);
    new_body.extend(std::iter::repeat(b' ').take(pad_len));
    new_body.extend_from_slice(&body[insert_pos..]);
    if new_body.len() != target_body_len {
        return Err(anyhow::anyhow!(
            "padding failed: expected body length {target_body_len}, got {}",
            new_body.len()
        ));
    }

    let headers_str = std::str::from_utf8(headers)?;
    let lines: Vec<&str> = headers_str.split("\r\n").collect();
    let mut wire = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if i > 0 {
            wire.extend_from_slice(b"\r\n");
        }
        if let Some((key, _)) = line.split_once(':') {
            if key.eq_ignore_ascii_case("content-length") {
                wire.extend_from_slice(format!("Content-Length: {target_body_len}").as_bytes());
                continue;
            }
        }
        wire.extend_from_slice(line.as_bytes());
    }
    wire.extend_from_slice(b"\r\n\r\n");
    wire.extend_from_slice(&new_body);
    Ok(wire)
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
