use std::{future::Future, sync::Arc};

use rustls::{crypto::ring, version::TLS13, ClientConfig, RootCertStore};

use crate::key_log::KeyLogVec;

pub trait ProxyClient {
    fn proxy_url(&self) -> &str;

    fn server_name(&self) -> &str;

    fn load_client_config(&self, key_log: Arc<KeyLogVec>) -> Arc<ClientConfig> {
        let _ = ring::default_provider().install_default();

        let mut roots = RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().expect("could not load platform certs")
        {
            roots.add(cert).unwrap();
        }

        let mut config = ClientConfig::builder_with_protocol_versions(&[&TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth();

        config.key_log = key_log;

        Arc::new(config)
    }

    fn execute<'a>(
        &'a self,
        data: &'a [u8],
    ) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send + 'a
    where
        Self: Sized + Sync;
}
