use btc::btc_functions;

use eth::eth_functions::perform_eth_handshake;
use tokio::io::AsyncWriteExt;
use utils::helper_functions::*;

mod utils{pub(crate) mod helper_functions;}
mod btc{pub(crate) mod btc_functions;}
mod eth{pub(crate) mod eth_functions; pub(crate) mod ecies;  pub(crate) mod handshake; pub(crate) mod hash_mac; pub(crate) mod secret;}

#[tokio::main]
async fn main() {
    let btc_node_ip = "162.55.130.189";
    let eth_node_ip = "23.92.70.178";
    let eth_public_key = "000314fd109a892573fe8ca8adfd2ed2a5259b3ca98a9b5a2e7f6fa495b5f258565861bf378cb4c2f250a06d9aa008d770c9c87a7364ae25fb3f29fa92af375f";
    let _ = bitcoin_handshake(btc_node_ip).await;
    let _ = etheruem_handshake(eth_node_ip, eth_public_key).await;
}

async fn bitcoin_handshake(btc_node_ip: &str) -> Result<(),()>{
    let mut stream = match tcp_handshake(btc_node_ip, 8333).await{
        Ok(stream) => stream,
        Err(err) => {
            println!("tcp_handshake: {}", err);
            return Err(());
        },
    };

    let nonce = generate_nonce();
    match btc_functions::send_version_message(&mut stream, 70033, nonce, 0).await{
        Ok(stream) => stream,
        Err(err) => {
            let _ = stream.shutdown().await;
            println!("send_version_message: {}", err);
            return Err(());
        },
    };

    match btc_functions::receive_version_message(&mut stream, nonce).await{
        Ok(version) => version,
        Err(err) => {
            let _ = stream.shutdown().await;
            println!("receive_version_message: {}", err);
            return Err(());
        },
    };

    match btc_functions::send_verack_message(&mut stream).await{
        Ok(stream) => stream,
        Err(err) => {
            let _ = stream.shutdown().await;
            println!("send_verack_message: {}", err);
            return Err(());
        },
    };

    match btc_functions::receive_verack_message(&mut stream).await{
        Ok(stream) => stream,
        Err(err) => {
            let _ = stream.shutdown().await;
            println!("receive_verack_message: {}", err);
            return Err(());
        },
    };

    return Ok(());
}

#[tokio::test]
async fn bitcoin_handshake_test() {
    let btc_node_ip = "162.55.130.189";
    let result = bitcoin_handshake(btc_node_ip).await;
    assert_eq!(result, Ok(()));
}

async fn etheruem_handshake(eth_node_ip: &str, public_key: &str)-> Result<(),()>{
    let mut stream = match tcp_handshake(eth_node_ip, 30304).await{
        Ok(stream) => stream,
        Err(err) => {
            println!("tcp_handshake: {}", err);
            return Err(());
        },
    };

    let  _res = match perform_eth_handshake(&mut stream, public_key).await{
        Ok(stream) => stream,
        Err(err) => {
            println!("perform_eth_handshake: {}", err);
            return Err(());
        },
    };

    return Err(());
}