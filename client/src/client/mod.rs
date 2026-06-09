use std::{future::Future, sync::Arc};

use bytes::Bytes;
use rig_core::{
    http_client::{
        self, HttpClientExt, LazyBody, MultipartForm, Request, Response, StreamingResponse,
    },
    providers::openai::OpenAICompletionsExt,
    wasm_compat::WasmCompatSend,
};

pub mod proxy;
use crate::utils::{decode_response, encode_request, http_client_error};
pub use proxy::ProxyClient;

#[derive(Clone, Debug, Default)]
pub struct ZKClient {
    http_client: reqwest::Client,
    proxy_url: Arc<str>,
    server_name: Arc<str>,
}

impl ZKClient {
    pub fn new(proxy_url: impl Into<String>) -> Self {
        Self {
            http_client: reqwest::Client::default(),
            proxy_url: Arc::from(proxy_url.into()),
            server_name: Arc::from("dashscope.aliyuncs.com"),
        }
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
        println!("=============hello from zkclient send===============");
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

#[cfg(test)]
mod tests {
    use std::env;

    use crate::client::Client;
    use rig_core::{client::CompletionClient, completion::Prompt};

    #[tokio::test]
    async fn test_client() {
        dotenvy::dotenv().ok();
        let api_key = env::var("QWEN_API_KEY").expect("QWEN_API_KEY must be set");
        let base_url = env::var("QWEN_BASE_URL")
            .unwrap_or_else(|_| "https://dashscope.aliyuncs.com/compatible-mode/v1".to_string());

        let zk_client = crate::client::ZKClient::new("127.0.0.1:9100");

        let client = Client::builder()
            .api_key(api_key)
            .base_url(base_url)
            .http_client(zk_client)
            .build()
            .unwrap();

        let agent = client
            .agent("qwen3.6-plus")
            .preamble("You are a calculator here to help the user perform arithmetic operations.")
            .build();

        let response = agent.prompt("Calculate 2 - 5.").await.unwrap();
        println!("\n\n\n{response}");
    }
}
