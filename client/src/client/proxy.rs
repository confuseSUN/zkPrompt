use std::{future::Future, sync::Arc};

use rustls::{crypto::ring, version::TLS13, ClientConfig, RootCertStore};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;
use webpki::types::ServerName;

use crate::{key_log::KeyLogVec, utils::check_and_padding};

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
        Self: Sync,
    {
        async move {
            println!("before padding: {:?}\n", String::from_utf8_lossy(data));
            let request = check_and_padding(data)?;
            println!("after padding: {:?}", String::from_utf8_lossy(&request));

            let proxy_stream = TcpStream::connect(self.proxy_url()).await?;

            let key_log = Arc::new(KeyLogVec::new("client_keylog"));
            let config = self.load_client_config(key_log);

            let connector = TlsConnector::from(config.clone());
            let server_name =
                ServerName::try_from(self.server_name().to_owned()).expect("Invalid server name");
            let mut tls_stream = connector.connect(server_name, proxy_stream).await?;

            tls_stream.write_all(&request).await?;

            let mut data = vec![];
            let mut buffer = [0u8; 8192];
            loop {
                let n = tls_stream.read(&mut buffer).await?;
                if n == 0 {
                    break;
                }
                data.extend(&buffer[..n]);
            }

            println!("\n\n\n{:?}", config.key_log);

            Ok(data)
        }
    }
}
