use std::io::ErrorKind;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use secp256k1::{PublicKey, SecretKey};
use rlp::{Decodable, Encodable};
use crate::eth::handshake::Handshake;

//Ecies and Rlp decoding bases off https://github.com/mchristou/ethereum-handshake/

pub async fn perform_eth_handshake(stream: &mut TcpStream, node_public_key: &str) -> Result<(),std::io::Error> {
    let private_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
    let id_decoded = match hex::decode(node_public_key.trim()){
        Ok(id_decoded) => id_decoded,
        Err(_) => return Err(std::io::Error::new(ErrorKind::Other, "Invalid public key")),
    };

    let public_key = match convert_bytes_to_public_key(&id_decoded){
        Ok(public_key) => public_key,
        Err(_) => return Err(std::io::Error::new(ErrorKind::Other, "Invalid public key")),
    };

    let mut handshake = Handshake::new(private_key, public_key);

    let auth_encrypted = handshake.auth();
    match stream.write(&auth_encrypted).await{
        Ok(_) => {},
        Err(_) => return Err(std::io::Error::new(ErrorKind::Other, "Unable to send auth data")),
    };

    println!("Auth data sent");

    let mut buf = [0_u8; 1024];
    let response = match stream.read(&mut buf).await{
        Ok(response) => response,
        Err(_) => return Err(std::io::Error::new(ErrorKind::Other, "Invalid response recieved after auth message")) ,
    };

    if response == 0 {
        return Err(std::io::Error::new(ErrorKind::Other, "Invalid response recieved after auth message"));
    }

    let mut bytes_used = 0u16;
    let decrypted_bytes = match handshake.decrypt(&mut buf, &mut bytes_used){
        Ok(decrypted_bytes) => decrypted_bytes,
        Err(_) => return Err(std::io::Error::new(ErrorKind::Other, "Unable to decrypt response")),
    };

    println!("Hello message recieved:{:?}", decrypted_bytes);
    if bytes_used == response as u16 {
        return Err(std::io::Error::new(ErrorKind::Other, "Recipient's response does not contain the Hello message"));
    }

    match handshake.derive_secrets(decrypted_bytes){
        Ok(_) => {},
        Err(_) => return Err(std::io::Error::new(ErrorKind::Other, "Unable to derive secrects from decrypted response")),
    };

    let hello_message_frame = handshake.hello_message();
    let hello_response  = match stream.write(&hello_message_frame).await{
        Ok(hello_response) => hello_response,
        Err(_) => return Err(std::io::Error::new(ErrorKind::Other, "Unable to send hello message")),
    };

    if hello_response == 0 {
        return Err(std::io::Error::new(ErrorKind::Other, "Invalid response recieved after hello message"));
    }

    let frame = match handshake.read_frame(&mut buf[bytes_used as usize..response]){
        Ok(frame) => frame,
        Err(_) => return Err(std::io::Error::new(ErrorKind::Other, "Unable to read frame")) ,
    };

    match decode_hello_message_frame(frame){
        Ok(_) => return Ok(()),
        Err(err) => return Err(err),
    };
}

pub fn convert_bytes_to_public_key(data: &[u8]) -> Result<PublicKey, std::io::Error> {
    let mut s = [4_u8; 65];
    s[1..].copy_from_slice(data);

    match PublicKey::from_slice(&s){
        Ok(public_key) => return Ok(public_key),
        Err(_) => return Err(std::io::Error::new(ErrorKind::Other, "Invalid public key")) ,
    };
}

pub fn decode_hello_message_frame(frame_bytes: Vec<u8>) -> Result<HelloMessage, std::io::Error> {
    let m_id: u8 = match rlp::decode(&[frame_bytes[0]]){
        Ok(m_id) => m_id,
        Err(_) => return Err(std::io::Error::new(ErrorKind::Other, "Unable to read id for rlp")) ,
    };

    if m_id == 0 {
        let hello_message: HelloMessage = match rlp::decode(&frame_bytes[1..]){
            Ok(message) => message,
            Err(_) => return Err(std::io::Error::new(ErrorKind::Other, "Invalid hello message for rlp")) ,
        };

        return Ok(hello_message);

    }else{
        let disconnect_message: Disconnect = match rlp::decode(&frame_bytes[1..]){
            Ok(message) => message,
            Err(_) => return Err(std::io::Error::new(ErrorKind::Other, "Invalid disconnect message for rlp")) ,
        };

        return Err(std::io::Error::new(ErrorKind::Other, format!("Disconnect message from target node: \n{:?}", disconnect_message)));
    }
}

#[derive(Debug)]
pub struct HelloMessage {
    pub protocol_version: usize,
    pub client_version: String,
    pub capabilities: Vec<Capability>,
    pub port: u16,
    pub id: PublicKey,
}

#[derive(Debug)]
pub struct Capability {
    pub name: String,
    pub version: usize,
}

#[derive(Debug)]
pub struct Disconnect {
    pub reason: usize,
}

impl Encodable for Disconnect {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.begin_list(1);
        s.append(&self.reason);
    }
}

impl Decodable for Disconnect {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        Ok(Self {
            reason: rlp.val_at(0)?,
        })
    }
}

impl Encodable for HelloMessage {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.begin_list(5);
        s.append(&self.protocol_version);
        s.append(&self.client_version);
        s.append_list(&self.capabilities);
        s.append(&self.port);

        let id = &self.id.serialize_uncompressed()[1..65];
        s.append(&id);
    }
}

impl Encodable for Capability {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.begin_list(2);
        s.append(&self.name);
        s.append(&self.version);
    }
}

impl Decodable for HelloMessage {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        let protocol_version: usize = rlp.val_at(0)?;
        let client_version: String = rlp.val_at(1)?;
        let capabilities: Vec<Capability> = rlp.list_at(2)?;
        let port: u16 = rlp.val_at(3)?;
        let id: Vec<u8> = rlp.val_at(4)?;

        let mut s = [0_u8; 65];
        s[0] = 4;
        s[1..].copy_from_slice(&id);
        let id = match PublicKey::from_slice(&s){
            Ok(id) => id,
            Err(_) => return Err(rlp::DecoderError::Custom("Unbale to decode public key")),
        };

        Ok(Self {
            protocol_version,
            client_version,
            capabilities,
            port,
            id,
        })
    }
}

impl Decodable for Capability {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        let name: String = rlp.val_at(0)?;
        let ver: usize = rlp.val_at(1)?;

        Ok(Self { name, version: ver })
    }
}