pub mod client;
pub mod key_log;
pub mod prove;
pub mod utils;

pub use client::{Client, ZKClient};
pub use prove::{ProveMaterials, ProveResult};
pub use utils::PaddedRequest;

#[cfg(test)]
mod tests {

    use ring::aead;
    use rustls::{
        crypto::{
            cipher::{make_tls13_aad, Nonce, PrefixedPayload},
            ring::tls13::{Tls13MessageEncrypter, TLS13_CHACHA20_POLY1305_SHA256},
            tls13::OkmBlock,
        },
        tls13::key_schedule::{derive_traffic_iv, derive_traffic_key},
    };

    #[test]
    fn test_chacha20_poly1305() {
        let secret_bytes = hex::decode("").unwrap();
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
            let bytes = hex::decode("0000000000").unwrap();
            PrefixedPayload(bytes)
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

        println!("key:{}", hex::encode(key.as_ref()));
        println!("nonce:{:?}", nonce_copy);
        println!("ct:{:?}", paypload.as_ref());

        println!("tag:{:?}", _tag.as_ref());
    }
}
