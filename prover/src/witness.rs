use std::env;

use anyhow::{anyhow, Context};
use ark_bn254::Fr;

use crate::{
    commitment::{cipher_commitment, prompt_commitment},
    openai::req::ReqVar,
};

pub fn configure_env_from_wire(wire: &[u8]) -> anyhow::Result<()> {
    const SEP: &[u8] = b"\r\n\r\n";
    let header_end = wire
        .windows(SEP.len())
        .position(|window| window == SEP)
        .ok_or_else(|| anyhow!("HTTP request missing header/body separator"))?;
    let headers = std::str::from_utf8(&wire[..header_end])?;
    let mut lines = headers.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| anyhow!("HTTP request missing request line"))?;
    let basepath = request_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow!("HTTP request line missing path"))?;
    env::set_var("BASEPATH", basepath);

    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        match name.trim().to_ascii_lowercase().as_str() {
            "host" => env::set_var("HOST", value.trim()),
            "authorization" => {
                let api_key = value
                    .trim()
                    .strip_prefix("Bearer ")
                    .or_else(|| value.trim().strip_prefix("bearer "))
                    .ok_or_else(|| anyhow!("authorization header missing bearer token"))?;
                env::set_var("API_KEY", api_key);
            }
            "content-length" => env::set_var("CONTENT_LENGTH", value.trim()),
            _ => {}
        }
    }

    env::var("CONTENT_LENGTH").context("CONTENT_LENGTH missing from HTTP wire")?;
    Ok(())
}

pub fn prompt_region_from_wire(wire: &[u8]) -> anyhow::Result<Vec<u8>> {
    configure_env_from_wire(wire)?;
    let content_length: usize = env::var("CONTENT_LENGTH")?.parse()?;
    let prompt_start = ReqVar::<Fr>::new(&[], 0).prompt_start();
    if wire.len() < prompt_start + content_length {
        return Err(anyhow!(
            "wire request too short for prompt region: {} < {}",
            wire.len(),
            prompt_start + content_length
        ));
    }
    Ok(wire[prompt_start..prompt_start + content_length].to_vec())
}

pub fn commitments_from_wire_and_tls(
    wire: &[u8],
    tls_application_data: &[u8],
) -> anyhow::Result<(Fr, Fr)> {
    let prompt = prompt_region_from_wire(wire)?;
    Ok((
        prompt_commitment(&prompt),
        cipher_commitment(tls_application_data),
    ))
}
