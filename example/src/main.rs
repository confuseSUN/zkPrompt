use std::env;

use client::{Client, ZKClient};
use rig_core::{client::CompletionClient, completion::Prompt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let api_key = env::var("API_KEY").map_err(|_| anyhow::anyhow!("API_KEY must be set"))?;
    let base_url = env::var("QWEN_BASE_URL")
        .unwrap_or_else(|_| "https://dashscope.aliyuncs.com/compatible-mode/v1".to_string());

    let zk_client = ZKClient::new("127.0.0.1:9100");

    let client = Client::builder()
        .api_key(api_key)
        .base_url(base_url)
        .http_client(zk_client.clone())
        .build()?;

    let agent = client
        .agent("qwen3.6-plus")
        .preamble("You are a calculator here to help the user perform arithmetic operations.")
        .build();

    // TODO: Prove for response
    let response = agent.prompt("Calculate 2 - 5.").await?;

    zk_client.prove().unwrap();

    println!("\n\n\n{response}");
    Ok(())
}
