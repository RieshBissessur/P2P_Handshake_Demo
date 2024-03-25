use btc::btc_functions;

use tokio::io::AsyncWriteExt;
use utils::helper_functions::*;

mod utils{pub(crate) mod helper_functions;}
mod btc{pub(crate) mod btc_functions;}

#[tokio::main]
async fn main() {
    let btc_node_ip = "13.247.54.166:8333";
    let _ = bitcoin_handshake(btc_node_ip).await;

}

async fn bitcoin_handshake(btc_node_ip: &str) -> Result<(),()>{
    let mut stream = match tcp_handshake(btc_node_ip).await{
        Ok(stream) => stream,
        Err(err) => {
            println!("tcp_handshake: {}", err);
            return Err(());
        },
    };

    let nonce = generate_nonce();
    match btc_functions::send_version_message(&mut stream, 70015, nonce, 0).await{
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

    let command_type = match btc_functions::receive_verack_message(&mut stream).await{
        Ok(stream) => stream,
        Err(err) => {
            let _ = stream.shutdown().await;
            println!("receive_verack_message: {}", err);
            return Err(());
        },
    };

    if !command_type.contains("verack") && !command_type.contains("sendcmpct") && !command_type.contains("sendheaders") {
        println!("Incorrect command recieved from node: {}", command_type);
        let _ = stream.shutdown().await;
        return Err(());
    }

    let _ = stream.shutdown().await;

    return Ok(());
}

#[tokio::test]
async fn bitcoin_handshake_test_node_1() {
    let btc_node_ip = "13.247.54.166:8333";
    let result = bitcoin_handshake(btc_node_ip).await;
    assert_eq!(result, Ok(()));
}

#[tokio::test]
async fn bitcoin_handshake_test_node_2() {
    let btc_node_ip = "217.182.198.226:8333";
    let result = bitcoin_handshake(btc_node_ip).await;
    assert_eq!(result, Ok(()));
}

#[tokio::test]
async fn bitcoin_handshake_test_node_3() {
    let btc_node_ip = "136.49.63.216:8333";
    let result = bitcoin_handshake(btc_node_ip).await;
    assert_eq!(result, Ok(()));
}