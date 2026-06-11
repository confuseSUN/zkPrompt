use anyhow::{anyhow, bail, Context};
use serde::Deserialize;

const HTTP_BODY_SEP: &[u8] = b"\r\n\r\n";
const USER_CONTENT_MARKER: &[u8] = br#""role":"user","content":""#;

/// Fixed HTTP template parameters shared by the circuit and the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestConfig {
    pub host: String,
    pub basepath: String,
    pub api_key: String,
    pub content_length: usize,
}

impl RequestConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            host: std::env::var("HOST").context("HOST must be set")?,
            basepath: std::env::var("BASEPATH").context("BASEPATH must be set")?,
            api_key: std::env::var("API_KEY").context("API_KEY must be set")?,
            content_length: std::env::var("CONTENT_LENGTH")
                .context("CONTENT_LENGTH must be set")?
                .parse()
                .context("invalid CONTENT_LENGTH")?,
        })
    }

    pub fn req_line(&self) -> Vec<u8> {
        format!("POST {} HTTP/1.1\r\n", self.basepath).into_bytes()
    }

    pub fn host_header(&self) -> Vec<u8> {
        format!("Host: {}\r\n", self.host).into_bytes()
    }

    pub fn authorization_header(&self) -> Vec<u8> {
        format!("authorization: Bearer {}\r\n", self.api_key).into_bytes()
    }

    pub fn content_type_header(&self) -> Vec<u8> {
        b"content-type: application/json\r\n".to_vec()
    }

    pub fn content_length_header(&self) -> Vec<u8> {
        format!("Content-Length: {}\r\n", self.content_length).into_bytes()
    }

    pub fn connection_header(&self) -> Vec<u8> {
        b"Connection: close\r\n".to_vec()
    }

    pub fn header_sections(&self) -> [Vec<u8>; 6] {
        [
            self.req_line(),
            self.host_header(),
            self.authorization_header(),
            self.content_type_header(),
            self.content_length_header(),
            self.connection_header(),
        ]
    }

    /// Byte offset where the HTTP body starts.
    pub fn body_start(&self) -> usize {
        self.header_sections()
            .iter()
            .map(|section| section.len())
            .sum::<usize>()
            + 2
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaddedRequest {
    pub request: Vec<u8>,
    pub body: Vec<u8>,
}

#[derive(Debug)]
struct ParsedHeaders {
    host: String,
    basepath: String,
    api_key: String,
    content_type: String,
    connection: String,
}

pub fn split_http(data: &[u8]) -> anyhow::Result<(&[u8], &[u8])> {
    let sep_pos = data
        .windows(HTTP_BODY_SEP.len())
        .position(|window| window == HTTP_BODY_SEP)
        .ok_or_else(|| anyhow!("HTTP request missing header/body separator"))?;
    Ok((&data[..sep_pos], &data[sep_pos + HTTP_BODY_SEP.len()..]))
}

fn parse_headers(headers: &[u8]) -> anyhow::Result<ParsedHeaders> {
    let headers_str = std::str::from_utf8(headers)?;
    let mut lines = headers_str.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| anyhow!("HTTP request missing request line"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| anyhow!("HTTP request line missing method"))?;
    if method != "POST" {
        bail!("expected POST request, got {method}");
    }
    let basepath = parts
        .next()
        .ok_or_else(|| anyhow!("HTTP request line missing path"))?
        .to_string();

    let mut host = None;
    let mut api_key = None;
    let mut content_type = None;
    let mut connection = None;

    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "host" => host = Some(value.trim().to_string()),
            "authorization" => {
                let token = value
                    .trim()
                    .strip_prefix("Bearer ")
                    .or_else(|| value.trim().strip_prefix("bearer "))
                    .ok_or_else(|| anyhow!("authorization header missing bearer token"))?;
                api_key = Some(token.to_string());
            }
            "content-type" => content_type = Some(value.trim().to_string()),
            "connection" => connection = Some(value.trim().to_string()),
            _ => {}
        }
    }

    Ok(ParsedHeaders {
        host: host.ok_or_else(|| anyhow!("missing Host header"))?,
        basepath,
        api_key: api_key.ok_or_else(|| anyhow!("missing Authorization header"))?,
        content_type: content_type.ok_or_else(|| anyhow!("missing Content-Type header"))?,
        connection: connection.ok_or_else(|| anyhow!("missing Connection header"))?,
    })
}

fn validate_headers(parsed: &ParsedHeaders, config: &RequestConfig) -> anyhow::Result<()> {
    if parsed.host != config.host {
        bail!(
            "host mismatch: expected {}, got {}",
            config.host,
            parsed.host
        );
    }
    if parsed.basepath != config.basepath {
        bail!(
            "path mismatch: expected {}, got {}",
            config.basepath,
            parsed.basepath
        );
    }
    if parsed.api_key != config.api_key {
        bail!("api key mismatch");
    }
    if parsed.content_type != "application/json" {
        bail!(
            "content-type mismatch: expected application/json, got {}",
            parsed.content_type
        );
    }
    if !parsed.connection.eq_ignore_ascii_case("close") {
        bail!(
            "connection mismatch: expected close, got {}",
            parsed.connection
        );
    }
    Ok(())
}

fn validate_chat_body(body: &[u8]) -> anyhow::Result<()> {
    #[derive(Deserialize)]
    struct ChatRequest {
        model: String,
        messages: Vec<ChatMessage>,
    }

    #[derive(Deserialize)]
    struct ChatMessage {
        role: String,
    }

    let request: ChatRequest =
        serde_json::from_slice(body).context("invalid chat completion JSON body")?;
    if request.model.is_empty() {
        bail!("model must not be empty");
    }
    let has_system = request.messages.iter().any(|message| message.role == "system");
    let has_user = request.messages.iter().any(|message| message.role == "user");
    if !has_system || !has_user {
        bail!("chat completion must include system and user messages");
    }
    Ok(())
}

fn user_content_pad_position(body: &[u8]) -> anyhow::Result<usize> {
    let start = body
        .windows(USER_CONTENT_MARKER.len())
        .position(|window| window == USER_CONTENT_MARKER)
        .ok_or_else(|| anyhow!("user content field not found"))?;

    let mut pos = start + USER_CONTENT_MARKER.len();
    let mut escaped = false;
    while pos < body.len() {
        let byte = body[pos];
        if escaped {
            escaped = false;
        } else if byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            return Ok(pos);
        }
        pos += 1;
    }

    Err(anyhow!("user content field not found"))
}

pub fn pad_body(body: &[u8], target_len: usize) -> anyhow::Result<Vec<u8>> {
    if body.len() == target_len {
        return Ok(body.to_vec());
    }
    if body.len() > target_len {
        bail!(
            "request body length {} exceeds maximum {target_len}",
            body.len()
        );
    }

    let pad_len = target_len - body.len();
    let insert_pos = user_content_pad_position(body)?;

    let mut new_body = Vec::with_capacity(target_len);
    new_body.extend_from_slice(&body[..insert_pos]);
    new_body.extend(std::iter::repeat(b' ').take(pad_len));
    new_body.extend_from_slice(&body[insert_pos..]);
    if new_body.len() != target_len {
        bail!(
            "padding failed: expected body length {target_len}, got {}",
            new_body.len()
        );
    }
    Ok(new_body)
}

pub fn rebuild_request(
    headers: &[u8],
    body: &[u8],
    content_length: usize,
) -> anyhow::Result<Vec<u8>> {
    let headers_str = std::str::from_utf8(headers)?;
    let lines: Vec<&str> = headers_str.split("\r\n").collect();
    let mut wire = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if index > 0 {
            wire.extend_from_slice(b"\r\n");
        }
        if let Some((key, _)) = line.split_once(':') {
            if key.eq_ignore_ascii_case("content-length") {
                wire.extend_from_slice(format!("Content-Length: {content_length}").as_bytes());
                continue;
            }
        }
        wire.extend_from_slice(line.as_bytes());
    }
    wire.extend_from_slice(b"\r\n\r\n");
    wire.extend_from_slice(body);
    Ok(wire)
}

pub fn check_and_pad(config: &RequestConfig, data: &[u8]) -> anyhow::Result<PaddedRequest> {
    let (headers, body) = split_http(data)?;
    validate_headers(&parse_headers(headers)?, config)?;
    validate_chat_body(body)?;

    let target_len = config.content_length;
    if body.len() == target_len {
        return Ok(PaddedRequest {
            request: data.to_vec(),
            body: body.to_vec(),
        });
    }

    let new_body = pad_body(body, target_len)?;
    Ok(PaddedRequest {
        request: rebuild_request(headers, &new_body, target_len)?,
        body: new_body,
    })
}

pub fn body_region_from_wire(wire: &[u8], config: &RequestConfig) -> anyhow::Result<Vec<u8>> {
    let body_start = config.body_start();
    let body_end = body_start + config.content_length;
    if wire.len() < body_end {
        return Err(anyhow!(
            "wire request too short for body region: {} < {body_end}",
            wire.len()
        ));
    }
    Ok(wire[body_start..body_end].to_vec())
}
