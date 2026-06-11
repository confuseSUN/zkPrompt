use std::env;

use anyhow::{anyhow};
use ark_bn254::Fr;

use crate::{
    commitment::{cipher_commitment, prompt_commitment},
    openai::req::ReqVar,
};

pub fn prompt_region_from_wire(wire: &[u8]) -> anyhow::Result<Vec<u8>> {
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
