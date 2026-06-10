pub mod client;
pub mod key_log;
pub mod utils;

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
        let secret_bytes =
            hex::decode("e8b8314bb29549569339f22b2c035cb0e16034674165f170051c5f3544a1dc8a")
                .unwrap();
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
            let  bytes  = hex::decode("0000000000d8bca7ceadd23acc0acc34c4e5e954a5b3346c36efba3ada7042977b62c4c7cea32ab590fd589782f860ef3764abcba50eb7e8aa98ebadb50934ee37f2900e612c90a2be01fdb21b1dde399676b6ca7ed72bb92488d3672faa416d96981ecb06b73b6201aa9b70c5302d89f1314477fd361c37c5e57195d0c80a83204b06453a98a5b5f8bdbc06d07ccbcf5eb81051d478be86571cfb3d5dddaa7f24702fbca4c69b8d3b71d1a8a551384afdd7b29307a69c9c27e20068c59242276518b17aac77cefd28832031499956f2753b292c88fa23ca2cda9cc2c50e0f37fc3975ff039fb1694642b56ee31017cc5bd29de8f4c29847b952ec103a8c5acac4decae85b58ccbf6c21b0b400fcb726ac404c8706f3c6cd62d8353d2315ac35f84cfddb2056bdc95c70058a459e0b215f1bbb9ddf96d8cd400ffe8c7a135d9730f2a706a495e14a3642c1ba3798bf33bba23f41b85949ee13d01568219f04646dae08bd9799e822b7a364dc9333b043a476fce52a6f5695d32f02a2ae1f080341c337570b72da204d92cd33555e53476b8641d7e00533310c69588472a331d7725ef3c26787f892abcf28539e448740c64a0f22c60193fedf521a40ad079eddf4de95c48e46e16809f0d9ad8291774d8c24c9f12be1fb5924d8b734ea23d19110fc07025bd5778b1641d028644a77769d31fa8371df5fb70b0fe64a9115ef211cc0da2312f9f8dbdcca3c38949f559b005a9610b2da601880d7752dfaa768a37e564280c0f3d8a6382d6ba65440612c63becdc0421859fed493f2dac05f5acd25f9dc92b87138c0587482e6749c82378e2f5893cf9572a338c8aea3b811c6c63a864737ee7783a5289bfa5aee60f449b6e4e442f4c8aa24672db4a9fc1619483605d505721fe1d6b9635315a5e9e52961d3a0116bcce26d3b29f924ecb0793f727a19aea972eac54e1663b7dbce0eba05febaad39a95df6982858e626c5e7c29b232a5750741d5aa57ec98ae74805bba0c12b1f87d7b79d990a55305b4834cd6a324bf930675675f4c3076bb51a8891c360de81c09f0402c46b128f1263ae23613da154a7b92b3c91fede54b5cc44937d83c321ffe462fee5a01e0e0900605290bb8363098af0e7170d1d80dd563abe2a1a509583ac7b40ef6c9953ca2d248e4a91c827049b7e063f20129eb7af4fa70285345b34b8fd7ad3df409b01fa15b27295d95930a3909d22a255d1d34b0bbdfdb78bd9a6b3c664d5c827beeb9474c5f55679ffb6400d4bdeab917ff35ee88495a6e346713f08950b475bd9f5f8beeb4e5ab91e5799e0c2a4632fffbfede73cd9a3a9c016499b4e45d0a07747155626fb4887703022a921fc2566c4750942c0098711f5263f5e7534da00b7540539fdfd6f6bc667f180ca86ec1c69f9bd4e7ba081ccb772b3dd935a006fd6ed76fdc54e911b9e3496dc639f4f1cec39c2e905d77b92a3b7334cb1e4d46803cade033e912cc9b2f049869810f94557f3f46cc4afcd55a36f6541f825a1ea91dbadf77c09b4f0aa1d25bd04ffbab68b3232f8c11759d2e347d0ec004f8e108c5c0ad9bbac0d11063e19b26320e25dd0744ae371499af41d885dd574214d817daec8c2edc08189ccd4e2294abe33dd1578170bdec6546a919703ed5534cff31ee042ce5fa751fb527eff461967db4d56c5c7686672d458e696feaede1bc74675e62dfc04e6ef9d49e676e066ac6fcf1b79d8a0262b3352f564223bb1c90a5f95b0354f84558fda0aafcc20569d2bc1183817").unwrap();
            PrefixedPayload(bytes)
        };
        let aad = aead::Aad::from(make_tls13_aad(paypload.len()));

        let seq = 0;
        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&encrypter.iv, seq).0);
        let nonce_copy = nonce.as_ref().to_vec();

        let _tag = encrypter
            .enc_key
            .seal_in_place_separate_tag(nonce, aad, paypload.as_mut())
            .unwrap();

        println!("key:{}", hex::encode(key.as_ref()));
        println!("nonce:{}", hex::encode(nonce_copy));
        println!("ct:{}", hex::encode(paypload.as_ref()));
    }
}
