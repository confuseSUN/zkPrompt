use ark_bn254::Fr;

use crate::{
    commitment::{cipher_commitment, prompt_commitment},
    openai::{body_region_from_wire, RequestConfig},
};

pub fn prompt_region_from_wire(wire: &[u8], config: &RequestConfig) -> anyhow::Result<Vec<u8>> {
    body_region_from_wire(wire, config)
}

pub fn commitments_from_wire_and_tls(
    wire: &[u8],
    tls_application_data: &[u8],
    config: &RequestConfig,
) -> anyhow::Result<(Fr, Fr)> {
    let prompt = prompt_region_from_wire(wire, config)?;
    Ok((
        prompt_commitment(&prompt),
        cipher_commitment(tls_application_data),
    ))
}
