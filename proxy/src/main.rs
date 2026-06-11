mod tls;

use anyhow::Result;
use clap::Parser;
use hickory_resolver::TokioAsyncResolver;
use prover::commitment::cipher_commitment;
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
};

async fn forward(mut from: ReadHalf<TcpStream>, mut to: WriteHalf<TcpStream>) -> Result<()> {
    let mut pending = Vec::new();
    let mut cipher_stream = Vec::new();
    let mut buffer = [0u8; 8192];

    loop {
        let n = from.read(&mut buffer).await?;
        if n == 0 {
            break;
        }

        let chunk = &buffer[..n];
        pending.extend_from_slice(chunk);

        let app_data = tls::drain_application_data(&mut pending);
        if !app_data.is_empty() {
            cipher_stream.extend(&app_data);

            println!("{:?}", cipher_stream);

            let commitment = cipher_commitment(&cipher_stream);
            println!(
                "cipher commitment: {commitment} ({} bytes application data)",
                cipher_stream.len()
            );
        }

        to.write_all(chunk).await?;
    }

    Ok(())
}

async fn handle_client(client_stream: TcpStream, addr: SocketAddr) -> Result<()> {
    let target_stream = TcpStream::connect(addr).await?;

    let (client_reader, mut client_writer) = tokio::io::split(client_stream);
    let (mut target_reader, target_writer) = tokio::io::split(target_stream);

    tokio::spawn(forward(client_reader, target_writer));

    tokio::io::copy(&mut target_reader, &mut client_writer).await?;

    Ok(())
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Command {
    /// Service port
    #[arg(short, long, env = "PORT", default_value = "9100")]
    port: u16,

    /// Forward host service, e.g. api.openai.com
    #[arg(short, long, env = "FORWARD")]
    forward: String,
}

// cargo run -p proxy -- --forward dashscope.aliyuncs.com --port 9100
#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let args = Command::parse();

    let self_addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    let listener = TcpListener::bind(self_addr).await.unwrap();
    let res = TokioAsyncResolver::tokio_from_system_conf()
        .unwrap()
        .lookup_ip(&args.forward)
        .await
        .unwrap();
    let server_ip = res.iter().next().expect("no addresses returned!");
    let server_addr = SocketAddr::new(server_ip, 443);

    println!("Listening on 0.0.0.0:{}", args.port);
    println!("Forwarding to {} -> {}", args.forward, server_addr);

    loop {
        let (client_stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let _ = handle_client(client_stream, server_addr).await;
        });
    }
}
