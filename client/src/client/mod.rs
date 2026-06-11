use std::{future::Future, sync::Arc};

use bytes::Bytes;
use rig_core::{
    http_client::{
        self, HttpClientExt, LazyBody, MultipartForm, Request, Response, StreamingResponse,
    },
    providers::openai::OpenAICompletionsExt,
    wasm_compat::WasmCompatSend,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;
use webpki::types::ServerName;

pub mod proxy;
use crate::{
    key_log::KeyLogVec,
    prove::{new_prove_session, ProveSession},
    utils::{check_and_padding, decode_response, encode_request, http_client_error},
    ProveMaterials,
};
pub use proxy::ProxyClient;

#[derive(Clone, Debug)]
pub struct ZKClient {
    http_client: reqwest::Client,
    proxy_url: Arc<str>,
    server_name: Arc<str>,
    session: ProveSession,
}

impl Default for ZKClient {
    fn default() -> Self {
        Self::new("127.0.0.1:9100")
    }
}

impl ZKClient {
    pub fn new(proxy_url: impl Into<String>) -> Self {
        Self {
            http_client: reqwest::Client::default(),
            proxy_url: Arc::from(proxy_url.into()),
            server_name: Arc::from("dashscope.aliyuncs.com"),
            session: new_prove_session(),
        }
    }

    pub(crate) fn prove_session(&self) -> &ProveSession {
        &self.session
    }

    pub fn prove_materials(&self) -> Option<ProveMaterials> {
        self.session.lock().unwrap().clone()
    }

    pub fn proxy_url(&self) -> &str {
        &self.proxy_url
    }

    pub fn with_server_name(mut self, server_name: impl Into<String>) -> Self {
        self.server_name = Arc::from(server_name.into());
        self
    }
}

impl ProxyClient for ZKClient {
    fn proxy_url(&self) -> &str {
        &self.proxy_url
    }

    fn server_name(&self) -> &str {
        &self.server_name
    }

    fn execute<'a>(
        &'a self,
        data: &'a [u8],
    ) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send + 'a {
        async move {
            let padded = check_and_padding(data)?;

            let proxy_stream = TcpStream::connect(self.proxy_url()).await?;
            let key_log = Arc::new(KeyLogVec::new("client_keylog"));
            let config = self.load_client_config(key_log.clone());

            let connector = TlsConnector::from(config);
            let server_name =
                ServerName::try_from(self.server_name().to_owned()).expect("Invalid server name");
            let mut tls_stream = connector.connect(server_name, proxy_stream).await?;

            tls_stream.write_all(&padded.request).await?;

            let mut raw_response = vec![];
            let mut buffer = [0u8; 8192];
            loop {
                let n = tls_stream.read(&mut buffer).await?;
                if n == 0 {
                    break;
                }
                raw_response.extend(&buffer[..n]);
            }

            let materials = ProveMaterials {
                request: padded.request,
                body: padded.body,
                response: raw_response.clone(),
                keylog: key_log.take(),
            };
            *self.prove_session().lock().unwrap() = Some(materials);

            Ok(raw_response)
        }
    }
}

impl HttpClientExt for ZKClient {
    fn send<T, U>(
        &self,
        req: Request<T>,
    ) -> impl Future<Output = http_client::Result<Response<LazyBody<U>>>> + WasmCompatSend + 'static
    where
        T: Into<Bytes>,
        T: WasmCompatSend,
        U: From<Bytes>,
        U: WasmCompatSend + 'static,
    {
        let client = self.clone();
        let wire_request = encode_request(req);

        async move {
            let response = client
                .execute(&wire_request)
                .await
                .map_err(|error| http_client_error(error.to_string()))?;

            decode_response(response)
        }
    }

    fn send_multipart<U>(
        &self,
        req: Request<MultipartForm>,
    ) -> impl Future<Output = http_client::Result<Response<LazyBody<U>>>> + WasmCompatSend + 'static
    where
        U: From<Bytes>,
        U: WasmCompatSend + 'static,
    {
        let http_client = self.http_client.clone();

        async move { http_client.send_multipart(req).await }
    }

    fn send_streaming<T>(
        &self,
        req: Request<T>,
    ) -> impl Future<Output = http_client::Result<StreamingResponse>> + WasmCompatSend
    where
        T: Into<Bytes> + WasmCompatSend,
    {
        let http_client = self.http_client.clone();
        let (parts, body) = req.into_parts();
        let req = Request::from_parts(parts, body.into());

        async move { http_client.send_streaming(req).await }
    }
}

pub type Client<H = ZKClient> = rig_core::client::Client<OpenAICompletionsExt, H>;
