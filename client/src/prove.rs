use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::{
    rand::{RngCore, SeedableRng},
    test_rng,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use prover::{
    build_cs::ZkPrompt,
    commitment::{cipher_commitment, prompt_commitment},
};
use ring::aead;
use rustls::{
    crypto::{
        cipher::{make_tls13_aad, Nonce, PrefixedPayload},
        ring::tls13::{Tls13MessageEncrypter, TLS13_CHACHA20_POLY1305_SHA256},
        tls13::OkmBlock,
    },
    tls13::key_schedule::{derive_traffic_iv, derive_traffic_key},
};

use crate::key_log::KeyLogItem;

const CLIENT_TRAFFIC_SECRET_0: &str = "CLIENT_TRAFFIC_SECRET_0";
/// rustls `PrefixedPayload` reserved header slot (`HEADER_SIZE = 1 + 2 + 2`).
const PREFIXED_PAYLOAD_HEADER_LEN: usize = 5;

#[derive(Debug, Clone)]
pub struct ProveMaterials {
    pub request: Vec<u8>,
    pub body: Vec<u8>,
    pub response: Vec<u8>,
    pub keylog: Vec<KeyLogItem>,
}

#[derive(Debug, Clone)]
pub struct ProveResult {
    pub llm_response: String,
    pub prompt_commitment: Fr,
    pub cipher_commitment: Fr,
    pub proxy_cipher_commitment: Fr,
}

pub(crate) type ProveSession = Arc<Mutex<Option<ProveMaterials>>>;

pub fn new_prove_session() -> ProveSession {
    Arc::new(Mutex::new(None))
}

impl ProveMaterials {
    pub fn commitments(&self, proxy_cipher_commitment: Fr) -> anyhow::Result<(Fr, Fr)> {
        let prompt = prover::commitment::prompt_commitment(&self.body);
        Ok((prompt, proxy_cipher_commitment))
    }

    pub fn client_traffic_secret(&self) -> anyhow::Result<[u8; 32]> {
        let item = self
            .keylog
            .iter()
            .find(|item| item.label == CLIENT_TRAFFIC_SECRET_0)
            .ok_or_else(|| anyhow::anyhow!("{CLIENT_TRAFFIC_SECRET_0} not found in keylog"))?;

        item.secret.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!(
                "{CLIENT_TRAFFIC_SECRET_0} has invalid length {}",
                item.secret.len()
            )
        })
    }

    pub fn encrypt_with_chacha20(&self) -> anyhow::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let secret_bytes = self.client_traffic_secret()?;
        let secret = OkmBlock::new(&secret_bytes);

        let suite = TLS13_CHACHA20_POLY1305_SHA256.tls13().unwrap();

        let expander = suite.hkdf_provider.expander_for_okm(&secret);
        let key = derive_traffic_key(expander.as_ref(), suite.aead_alg);

        let iv = derive_traffic_iv(expander.as_ref());

        let encrypter = Tls13MessageEncrypter {
            enc_key: aead::LessSafeKey::new(
                aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key.as_ref()).unwrap(),
            ),
            iv,
        };

        let mut paypload = {
            let mut buf = Vec::with_capacity(PREFIXED_PAYLOAD_HEADER_LEN + self.request.len());
            buf.extend_from_slice(&[0u8; PREFIXED_PAYLOAD_HEADER_LEN]);
            buf.extend_from_slice(&self.request);
            PrefixedPayload(buf)
        };
        let aad = aead::Aad::from(make_tls13_aad(paypload.len()));

        // CLIENT_TRAFFIC_SECRET_0
        let seq = 0;
        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&encrypter.iv, seq).0);
        let nonce_copy = nonce.as_ref().to_vec();

        let _tag = encrypter
            .enc_key
            .seal_in_place_separate_tag(nonce, aad, paypload.as_mut())
            .unwrap();

        return Ok((
            paypload.as_ref().to_vec(),
            key.as_ref().to_vec(),
            nonce_copy,
        ));
    }
}

impl crate::client::ZKClient {
    pub fn prove(&self) -> anyhow::Result<()> {
        let materials = self
            .prove_session()
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| anyhow::anyhow!("no prove materials; send a request first"))?;

        let (cipher, key, nonce) = materials.encrypt_with_chacha20()?;

        let circuit = ZkPrompt::new(cipher.clone(), key, nonce, 1);

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit
            .clone()
            .generate_constraints(cs.clone())
            .map_err(|error| anyhow::anyhow!("circuit synthesis failed: {error}"))?;
        if !cs.is_satisfied().unwrap() {
            anyhow::bail!("circuit constraints not satisfied; HTTP wire does not match circuit template");
        }

        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());

        let (pk, vk) = Groth16::<Bn254>::setup(circuit.clone(), &mut rng).unwrap();
        let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();

        let start = Instant::now();
        let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), &mut rng).unwrap();
        println!("prove time: {:.2?}", start.elapsed());

        let public_inputs = vec![
            prompt_commitment(&materials.body), // from user
            cipher_commitment(&cipher),         // from proxy
        ];
        assert_eq!(public_inputs.len(), 2);

        assert!(Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof).unwrap());

        Ok(())
    }
}
