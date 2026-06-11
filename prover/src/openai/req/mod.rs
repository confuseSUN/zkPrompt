use ark_ff::PrimeField;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::r1cs::SynthesisError;

use crate::utils::enforce_equals;

use super::wire::RequestConfig;

pub struct ReqVar<F: PrimeField> {
    pub data_vars: Vec<UInt8<F>>,
    pub config: RequestConfig,
}

impl<F: PrimeField> ReqVar<F> {
    pub fn new(data_vars: &[UInt8<F>], config: RequestConfig) -> Self {
        Self {
            data_vars: data_vars.to_vec(),
            config,
        }
    }

    pub fn prompt_start(&self) -> usize {
        self.config.body_start()
    }

    pub fn generate_constraints(&self) -> Result<(), SynthesisError> {
        let sections = self.config.header_sections();
        let mut start = 0;

        for section in sections {
            let section_vars = section
                .iter()
                .map(|byte| UInt8::constant(*byte))
                .collect::<Vec<UInt8<F>>>();
            let end = start + section.len();
            enforce_equals(&section_vars, &self.data_vars[start..end])?;
            start = end;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use ark_bn254::Fr;
    use ark_r1cs_std::uint8::UInt8;

    use crate::openai::{req::ReqVar, RequestConfig};

    #[test]
    fn test_req_constraint() {
        let config = RequestConfig {
            host: "dashscope.aliyuncs.com".into(),
            basepath: "/compatible-mode/v1/chat/completions".into(),
            api_key: "sk".into(),
            content_length: 211,
        };
        let bytes = hex::decode(
            "504f5354202f636f6d70617469626c652d6d6f64652f76312f636861742f636f6d706c6574696f6e7320485454502f312e310d0a486f73743a206461736873636f70652e616c6979756e63732e636f6d0d0a617574686f72697a6174696f6e3a2042656172657220736b0d0a636f6e74656e742d747970653a206170706c69636174696f6e2f6a736f6e0d0a436f6e74656e742d4c656e6774683a203231310d0a436f6e6e656374696f6e3a20636c6f73650d0a0d0a7b226d6f64656c223a227177656e332e362d706c7573222c226d65737361676573223a5b7b22726f6c65223a2273797374656d222c22636f6e74656e74223a5b7b2274797065223a2274657874222c2274657874223a22596f752061726520612063616c63756c61746f72206865726520746f2068656c7020746865207573657220706572666f726d2061726974686d65746963206f7065726174696f6e732e227d5d7d2c7b22726f6c65223a2275736572222c22636f6e74656e74223a2243616c63756c6174652032202d20352e227d5d7d",
        )
        .unwrap();

        let byte_vars = bytes
            .iter()
            .map(|byte| UInt8::constant(*byte))
            .collect::<Vec<UInt8<Fr>>>();

        let var = ReqVar::new(&byte_vars, config);
        var.generate_constraints().unwrap();
    }
}
