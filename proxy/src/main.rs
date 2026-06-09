use anyhow::Result;
use clap::Parser;
use hickory_resolver::TokioAsyncResolver;
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
};

/*

Data packet[23, 3, 3, 0, 53, 154, 103, 163, 134, 128, 117, 206, 103, 136, 101, 99, 130, 127, 143, 182, 7, 129, 252, 50, 250, 113, 1, 242, 195, 87, 6, 178, 255, 150, 32, 196, 45, 198, 207, 96, 14, 100, 180, 126, 104, 252, 144, 124, 99, 198, 136, 198, 100, 214, 195, 207, 127, 193]
0x17 = 23 表示 Application Data
03 03 表示version
0x35 = 53 表示长度

*/

async fn forward(mut from: ReadHalf<TcpStream>, mut to: WriteHalf<TcpStream>) -> Result<()> {
    loop {
        let mut data = vec![];
        let mut buffer = [0u8; 8192]; // read 8k buffer

        // TODO read more than 8k
        let n = from.read(&mut buffer).await?;
        if n == 0 {
            continue;
        }
        data.extend(&buffer[..n]);

        println!("read buffer: {}", data.len());

        // check the data is tls data
        if is_tls_handshake_packet(&data) {
            println!("TLS packet");
        } else {
            println!("Data packet{:?}", data);
            // TODO commitment for the prompt data
        }

        to.write_all(&data).await?;
    }

    // Ok(())
}

/// TLS Handshake signal 0x16
fn is_tls_handshake_packet(packet: &[u8]) -> bool {
    matches!(packet.first(), Some(&0x14) | Some(&0x15) | Some(&0x16))
}

async fn handle_client(client_stream: TcpStream, addr: SocketAddr) -> Result<()> {
    let target_stream = TcpStream::connect(addr).await?;

    let (client_reader, mut client_writer) = tokio::io::split(client_stream);
    let (mut target_reader, target_writer) = tokio::io::split(target_stream);

    // handle request transfer
    tokio::spawn(forward(client_reader, target_writer));

    // not handle response transfer
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

// cargo run -- --forward dashscope.aliyuncs.com --port 9100
// cargo run -- --forward www.rust-lang.org --port 9100
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
    let server_addr = SocketAddr::new(server_ip, 443); // use tls default port

    println!("Listening on 0.0.0.0:{}", args.port);
    println!("Forwarding to {} -> {}", args.forward, server_addr);

    loop {
        let (client_stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let _ = handle_client(client_stream, server_addr).await;
        });
    }
}
