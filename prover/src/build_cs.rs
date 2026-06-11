use std::env;

use ark_bn254::Fr;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    prelude::ToBitsGadget,
    uint32::UInt32,
    uint8::UInt8,
    R1CSVar,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

use crate::{
    chacha20::ChaCha20Var,
    mimc::{
        bn254::{constraint::MimcBn254Var, MimcBn254},
        MiMC,
    },
    openai::req::{traits::ReqConstraint, ReqVar},
    utils::compress_var,
};

#[derive(Clone)]
pub struct ZkPrompt {
    pub cipher_texts: Vec<u8>,
    pub key: Vec<u8>,
    pub nonce: Vec<u8>,
    pub count: u32,
}

impl ZkPrompt {
    pub fn new(cipher_texts: Vec<u8>, key: Vec<u8>, nonce: Vec<u8>, count: u32) -> Self {
        Self {
            cipher_texts,
            key,
            nonce,
            count,
        }
    }

    pub fn mock_ciucuit() -> Self {
        Self {
            cipher_texts: vec![0; 2020],
            key: vec![0; 32],
            nonce: vec![0; 12],
            count: 1,
        }
    }
}

impl ConstraintSynthesizer<Fr> for ZkPrompt {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let mut key_vars = vec![];
        for chunk in self.key.chunks(4) {
            let val = u32::from_le_bytes(chunk.try_into().unwrap());
            let var = UInt32::new_witness(ns!(cs, "alloc key"), || Ok(val))?;
            key_vars.push(var);
        }

        let mut nonce_vars = vec![];
        for chunk in self.nonce.chunks(4) {
            let val = u32::from_le_bytes(chunk.try_into().unwrap());
            let var = UInt32::new_witness(ns!(cs, "alloc key"), || Ok(val))?;
            nonce_vars.push(var);
        }

        let qr_constant_vars = vec![
            UInt32::new_constant(ns!(cs, "alloc constant"), 0x61707865).unwrap(),
            UInt32::new_constant(ns!(cs, "alloc constant"), 0x3320646e).unwrap(),
            UInt32::new_constant(ns!(cs, "alloc constant"), 0x79622d32).unwrap(),
            UInt32::new_constant(ns!(cs, "alloc constant"), 0x6b206574).unwrap(),
        ];

        let count_var = UInt32::new_witness(ns!(cs, "alloc count"), || Ok(self.count))?;
        let cipher_vars = self
            .cipher_texts
            .iter()
            .map(|x| UInt8::new_witness(ns!(cs, "alloc cipher"), || Ok(*x)).unwrap())
            .collect::<Vec<_>>();

        let mut chacha20 = ChaCha20Var::new(
            &qr_constant_vars,
            &key_vars,
            &nonce_vars,
            count_var,
            &cipher_vars,
        );
        chacha20.generate_constraints()?;

        let prompt_len = env::var("CONTENT_LENGTH").unwrap().parse().unwrap();
        let req_var = ReqVar::new(&chacha20.output_vars, prompt_len);
        req_var.generate_constraints()?;

        let start = req_var.prompt_start();
        let end = start + prompt_len;
        let prompt = &chacha20.output_vars[start..end];

        let mut round_constant_vars = vec![];
        for c in MimcBn254::ROUND_KEYS {
            round_constant_vars.push(FpVar::new_constant(ns!(cs, "alloc round keys"), c).unwrap());
        }
        let mimc_var = MimcBn254Var::new(1, &round_constant_vars, FpVar::zero());

        let mut prompt_bits = vec![];
        for p in prompt {
            prompt_bits.extend(p.to_bits_be()?);
        }
        let compress_prompt = compress_var(&prompt_bits, 250)?;
        let prompt_commitment = mimc_var.generate_constraints(&compress_prompt)[0].clone();

        let mut cipher_bits = vec![];
        for c in cipher_vars {
            cipher_bits.extend(c.to_bits_be()?);
        }
        let compress_cipher = compress_var(&cipher_bits, 250)?;
        let cipher_commitment = mimc_var.generate_constraints(&compress_cipher)[0].clone();

        let pi_prompt_commitment =
            FpVar::new_input(ns!(cs, "public prompt"), || prompt_commitment.value())?;
        pi_prompt_commitment.enforce_equal(&prompt_commitment)?;

        let pi_cipher_commitment =
            FpVar::new_input(ns!(cs, "public cipher"), || cipher_commitment.value())?;
        pi_cipher_commitment.enforce_equal(&cipher_commitment)?;

        println!("cs size:{}", cs.num_constraints());

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::{env, time::Instant};

    use ark_bn254::{Bn254, Fr};
    use ark_groth16::Groth16;
    use ark_r1cs_std::{alloc::AllocVar, uint32::UInt32, uint8::UInt8, R1CSVar};
    use ark_relations::{
        ns,
        r1cs::{ConstraintSynthesizer, ConstraintSystem},
    };
    use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_std::{
        rand::{RngCore, SeedableRng},
        test_rng,
    };

    use crate::{
        build_cs::ZkPrompt,
        chacha20::ChaCha20Var,
        commitment::{cipher_commitment, prompt_commitment},
        openai::req::{traits::ReqConstraint, ReqVar},
    };

    fn set_test_env() {
        env::set_var("HOST", "dashscope.aliyuncs.com");
        env::set_var("BASEPATH", "/compatible-mode/v1/chat/completions");
        env::set_var("API_KEY", "sk");
        env::set_var("CONTENT_LENGTH", "64");
    }

    fn http_plaintext_from_env() -> Vec<u8> {
        let content_length: usize = env::var("CONTENT_LENGTH").unwrap().parse().unwrap();
        let prompt_start = ReqVar::<Fr>::new(&[], 0).prompt_start();

        let mut plaintext = Vec::new();
        plaintext.extend(ReqVar::<Fr>::req_line());
        plaintext.extend(ReqVar::<Fr>::host());
        plaintext.extend(ReqVar::<Fr>::authorization());
        plaintext.extend(ReqVar::<Fr>::content_type());
        plaintext.extend(ReqVar::<Fr>::content_length());
        plaintext.extend(ReqVar::<Fr>::connection());
        plaintext.extend(b"\r\n");
        plaintext.resize(prompt_start + content_length, 0);
        plaintext
    }

    fn chacha_keystream(key: &[u8], nonce: &[u8], count: u32, len: usize) -> Vec<u8> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let key_vars = key
            .chunks(4)
            .map(|chunk| {
                UInt32::new_witness(ns!(cs, "key"), || {
                    Ok(u32::from_le_bytes(chunk.try_into().unwrap()))
                })
                .unwrap()
            })
            .collect::<Vec<_>>();
        let nonce_vars = nonce
            .chunks(4)
            .map(|chunk| {
                UInt32::new_witness(ns!(cs, "nonce"), || {
                    Ok(u32::from_le_bytes(chunk.try_into().unwrap()))
                })
                .unwrap()
            })
            .collect::<Vec<_>>();
        let count_var = UInt32::new_witness(ns!(cs, "count"), || Ok(count)).unwrap();
        let qr_constant_vars = vec![
            UInt32::new_constant(ns!(cs, "constant"), 0x61707865).unwrap(),
            UInt32::new_constant(ns!(cs, "constant"), 0x3320646e).unwrap(),
            UInt32::new_constant(ns!(cs, "constant"), 0x79622d32).unwrap(),
            UInt32::new_constant(ns!(cs, "constant"), 0x6b206574).unwrap(),
        ];
        let input_vars = (0..len)
            .map(|_| UInt8::new_witness(ns!(cs, "input"), || Ok(0u8)).unwrap())
            .collect::<Vec<_>>();

        let mut chacha20 = ChaCha20Var::new(
            &qr_constant_vars,
            &key_vars,
            &nonce_vars,
            count_var,
            &input_vars,
        );
        chacha20.generate_constraints().unwrap();

        chacha20
            .output_vars
            .iter()
            .map(|var| var.value().unwrap())
            .collect()
    }

    fn witness_from_env() -> ZkPrompt {
        let plaintext = http_plaintext_from_env();
        let key = vec![1u8; 32];
        let nonce = vec![2u8; 12];
        let count = 1;
        let keystream = chacha_keystream(&key, &nonce, count, plaintext.len());
        let cipher_texts = plaintext
            .iter()
            .zip(keystream.iter())
            .map(|(plain, stream)| plain ^ stream)
            .collect();

        ZkPrompt {
            cipher_texts,
            key,
            nonce,
            count,
        }
    }

    fn assert_circuit_satisfied(circuit: &ZkPrompt) {
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .clone()
            .generate_constraints(cs.clone())
            .expect("circuit constraints should be generated");
        assert!(cs.is_satisfied().unwrap());
    }

    fn public_inputs(circuit: &ZkPrompt) -> Vec<Fr> {
        let keystream = chacha_keystream(
            &circuit.key,
            &circuit.nonce,
            circuit.count,
            circuit.cipher_texts.len(),
        );
        let plaintext: Vec<u8> = circuit
            .cipher_texts
            .iter()
            .zip(keystream.iter())
            .map(|(cipher, stream)| cipher ^ stream)
            .collect();

        let content_length: usize = env::var("CONTENT_LENGTH").unwrap().parse().unwrap();
        let prompt_start = ReqVar::<Fr>::new(&[], 0).prompt_start();
        let prompt = &plaintext[prompt_start..prompt_start + content_length];

        vec![
            prompt_commitment(prompt),
            cipher_commitment(&circuit.cipher_texts),
        ]
    }

    #[test]
    fn test() {
        set_test_env();

        let circuit = witness_from_env();
        assert_circuit_satisfied(&circuit);

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let (pk, vk) = Groth16::<Bn254>::setup(circuit.clone(), &mut rng).unwrap();
        let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();

        let start = Instant::now();
        let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), &mut rng).unwrap();
        println!("prove time: {:.2?}", start.elapsed());

        let public_inputs = public_inputs(&circuit);
        assert_eq!(public_inputs.len(), 2);

        assert!(Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof).unwrap());
    }
}
