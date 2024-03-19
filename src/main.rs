use btc::btc_functions;
mod utils{pub(crate) mod helper_functions;}
mod btc{pub(crate) mod btc_functions;}

#[tokio::main]
async fn main() {
    let btc_node_ip = "162.55.130.189";
    let _ = bitcoin_handshake(btc_node_ip).await;
}

async fn bitcoin_handshake(btc_node_ip: &str) -> Result<(),()>{
    let mut stream = match btc_functions::tcp_handshake(btc_node_ip).await{
        Ok(stream) => stream,
        Err(err) => {
            println!("tcp_handshake: {}", err);
            return Err(());
        },
    };

    match btc_functions::send_version_message(&mut stream, 70033, 0301, 0).await{
        Ok(stream) => stream,
        Err(err) => {
            println!("send_version_message: {}", err);
            return Err(());
        },
    };

    match btc_functions::receive_version_message(&mut stream, 0301).await{
        Ok(version) => version,
        Err(err) => {
            println!("receive_version_message: {}", err);
            return Err(());
        },
    };

    match btc_functions::send_verack_message(&mut stream).await{
        Ok(stream) => stream,
        Err(err) => {
            println!("send_verack_message: {}", err);
            return Err(());
        },
    };

    match btc_functions::receive_verack_message(&mut stream).await{
        Ok(stream) => stream,
        Err(err) => {
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