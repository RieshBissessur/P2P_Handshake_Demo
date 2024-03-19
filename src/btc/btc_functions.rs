use std::io::ErrorKind;
use std::net::SocketAddr;
use std::ops::BitAnd;
use std::time::UNIX_EPOCH;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use std::str;
use crate::utils::helper_functions::*;


/// Message Structure
/// size  | field       | type      | description
/// ---   | -----       | ----      | ------------
//   4	  | magic	      | uint32_t	|Magic value indicating message origin network, and used to seek to next message when stream state is unknown
//  12	  |  command	  | char[12]	|ASCII string identifying the packet content, NULL padded (non-NULL padding results in packet rejected)
//  4	    |  length	    | uint32_t	|Length of payload in number of bytes
//  4	    |  checksum	  | uint32_t	|First 4 bytes of sha256(sha256(payload))
//  ?	    |  payload	  |  uchar[]	|The actual data

/// Version
/// size | field        | type     | description
/// ---  | -----        | ----     | ------------
/// 4    | version      | i32      | Identifies protocol version being used by the node
/// 8    | services     | u64      | bitfield of features to be enabled for this connection
/// 8    | timestamp    | i64      | standard UNIX timestamp in seconds
/// 26   | addr_recv    | net_addr | The network address of the node receiving this message
/// 26   | addr_from    | net_addr | Field can be ignored.
/// 8    | nonce        | u64      | Node random nonce
/// ?    | user_agent   | var_str  | User Agent (0x00 if string is 0 bytes long)
/// 4    | start_height | i32      | The last block received by the emitting node
/// 1    | relay        | bool     | Whether the remote peer should announce relayed transactions or not, see BIP 0037
/// *********************************************************
/// Almost all integers are encoded in little endian. Only IP or port number are encoded big endian.
/// *********************************************************

/// Network Address
/// size | field        | type     | description
/// ---  | -----        | ----     | ------------
//  4	   |  time	      | uint32	 | the Time (version >= 31402). Not present in version message.
//  8	   |  services	  | uint64_t | same service(s) listed in version
//  16   |  IPv6/4	    | char[16] | IPv6 address. Network byte order. The original client only supported IPv4 and only read the last 4 bytes to get the IPv4 address. However, the IPv4 address is written into the message as a 16 byte IPv4-mapped IPv6 address (12 bytes 00 00 00 00 00 00 00 00 00 00 FF FF, followed by the 4 bytes of the IPv4 address).
//  2	   |  port      	|uint16_t	 | port number, network byte order

pub const MAGIC_VALUE: [u8; 4] = [0xF9, 0xBE, 0xB4, 0xD9]; // Mainnet magic value
pub const VERSION_CMD: [u8; 12] = *b"version\0\0\0\0\0";
pub const VERACK_CMD: [u8; 12] = *b"verack\0\0\0\0\0\0";

pub async fn tcp_handshake(ip: &str)->Result<TcpStream, std::io::Error>{
  match TcpStream::connect((ip, 8333)).await{
    Ok(tcp) => return Ok(tcp),
    Err(err) => return Err(err),
  };
}

pub async fn send_version_message(stream: &mut TcpStream, version: u32, nonce: u64, start_height: u32) -> Result<(), std::io::Error> {

  // Add node version to payload
  let mut version_payload: Vec<u8> = vec![];
  version_payload.extend_from_slice(&version.to_le_bytes());

  // Add node version to payload
  let mut services: u64 = 0x0;
  services = services.bitand(*&0x1 as u64);
  version_payload.extend_from_slice(&services.to_le_bytes());

  // Get timestamp and add to payload
  let timpstamp = match std::time::SystemTime::now().duration_since(UNIX_EPOCH){ 
    Ok(timpstamp) => timpstamp,
    Err(_) => return Err(std::io::Error::new(ErrorKind::Other, "Invalid timestamp")),
  };

  let timestamp_int = timpstamp.as_secs() as u64;
  version_payload.extend_from_slice(&timestamp_int.to_le_bytes());
  
  // Get reciever address from TCP stream peer address and add to payload
  let reciever_address = match stream.peer_addr(){
    Ok(reciever_address) => reciever_address,
    Err(_) => return Err(std::io::Error::new(ErrorKind::Other, "Invalid TCP peer address")),
  };

  let reciever = match reciever_address{
    SocketAddr::V4(reciever) => reciever,
    SocketAddr::V6(_) => return Err(std::io::Error::new(ErrorKind::Other, "Invalid TCP peer address")),
  };

  let mut reciever_address_bytes: Vec<u8> = Vec::new();
  reciever_address_bytes.extend_from_slice(&services.to_le_bytes());
  let reciever_ip_addr_bytes = reciever.ip().to_ipv6_compatible().octets();
  reciever_address_bytes.extend_from_slice(&reciever_ip_addr_bytes);
  reciever_address_bytes.extend_from_slice(&reciever.port().to_be_bytes());
  version_payload.append(&mut reciever_address_bytes);
  
  // Get sender address from TCP stream local address and add to payload
  let sender_address = match stream.local_addr(){
    Ok(sender_address) => sender_address,
    Err(_) => return Err(std::io::Error::new(ErrorKind::Other, "Invalid local address")),
  };

  let sender = match sender_address{
    SocketAddr::V4(sender) => sender,
    SocketAddr::V6(_) => return Err(std::io::Error::new(ErrorKind::Other, "Invalid local address")),
  };

  let mut sender_address_bytes: Vec<u8> = Vec::new();
  sender_address_bytes.extend_from_slice(&services.to_le_bytes());
  let sender_ip_addr_bytes = sender.ip().to_ipv6_compatible().octets();
  sender_address_bytes.extend_from_slice(&sender_ip_addr_bytes);
  sender_address_bytes.extend_from_slice(&sender.port().to_be_bytes());
  version_payload.append(&mut sender_address_bytes);

  // Add nonce to payload
  version_payload.extend_from_slice(&nonce.to_le_bytes());

  // Add empty user agent to payload
  version_payload.extend_from_slice(&[0]);

  // Add start height to payload
  version_payload.extend_from_slice(&start_height.to_le_bytes());

  // Add relay to payload
  version_payload.extend_from_slice(&[0]);

  // Calculate checksum and payload length
  let checksum_bytes = calculate_checksum(&version_payload);
  let checksum = u32::from_le_bytes(checksum_bytes);
  let magic = u32::from_le_bytes(MAGIC_VALUE);
  let payload_len: [u8; 8] = version_payload.len().to_le_bytes();
  let mut payload_len_bytes = [0u8; 4];
  payload_len_bytes.clone_from_slice(&payload_len[..4]);

  // Create command details in byte vetor
  let mut command: Vec<u8> = vec![];
  command.extend_from_slice(&magic.to_le_bytes());
  command.extend_from_slice(&VERSION_CMD);
  command.extend_from_slice(&payload_len_bytes);
  command.extend_from_slice(&checksum.to_ne_bytes());
  command.extend_from_slice(&version_payload);

  // Send the command via TCP
  match stream.write_all(&command).await{
    Ok(_) => return Ok(()),
    Err(_) => return Err(std::io::Error::new(ErrorKind::Other, "Unable to send TCP packet")),
  };
}

pub async fn receive_version_message(stream: &mut TcpStream, nonce_sent: u64) -> Result<u32, std::io::Error> {
  let mut stream_reader = BufReader::new(stream);
  let received_bytes = match stream_reader.fill_buf().await {
      Ok(received_bytes) => received_bytes,
      Err(err) => return Err(std::io::Error::new(ErrorKind::Other, format!("Unable to recieve bytes: {}", err))),
  };

  // Remove command header from payload
  let mut command_bytes = received_bytes.to_vec();
  if command_bytes.len() > 20{
    command_bytes.drain(..20);
  }

  let version = match get_u32_from_byte_array(&mut command_bytes){
    Ok(version) => version,
    Err(_) => return Err(std::io::Error::new(ErrorKind::Other, "Invalid version")),
};

  println!("Version: {:?}", version);
  command_bytes.drain(..68);

  let nonce = match get_u64_from_byte_array(&mut command_bytes){
    Ok(nonce) => nonce,
    Err(_) => return Err(std::io::Error::new(ErrorKind::Other, "Invalid Nonce")),
  };

  if nonce_sent == nonce {
      return Err(std::io::Error::new(ErrorKind::Other, "Nonce is the same"));
  }

  if command_bytes.len() > 16{
    command_bytes.drain(..16);
  }
  
  Ok(version)
}

pub async fn send_verack_message(stream: &mut TcpStream) -> Result<(), std::io::Error> {
  let checksum = u32::from_le_bytes(calculate_checksum(&Vec::new()));
  let magic = u32::from_le_bytes(MAGIC_VALUE);
  let payload_len: Vec<u8>  = vec![0; 4];

  // Create command details in byte vetor
  let mut command: Vec<u8> = vec![];
  command.extend_from_slice(&magic.to_le_bytes());
  command.extend_from_slice(&VERACK_CMD);
  command.extend_from_slice(&payload_len);
  command.extend_from_slice(&checksum.to_ne_bytes());
  command.extend_from_slice(&Vec::new());

  // Send the command via TCP
  let _  = stream.write_all(&command).await;
  return Ok(());
}

pub async fn receive_verack_message(stream: &mut TcpStream) -> Result<String, std::io::Error> {
  let mut reader = BufReader::new(stream);
  let received_bytes = match reader.fill_buf().await {
      Ok(r) => r,
      Err(_e) => return Err(std::io::Error::new(ErrorKind::Other, "Unable to recieve bytes")),
  };

  // Remove message header from payload
  let mut command_bytes = received_bytes.to_vec();

  if command_bytes.len() > 8{
    command_bytes.drain(..8);
  }

  let mut command: [u8; 12] = [0; 12];
  if command_bytes.len() > 12 {
    command.copy_from_slice(&command_bytes[..12]);
  }

  let command_str = match str::from_utf8(&command).map(|s| s.to_owned()){
    Ok(command_str) => command_str,
    Err(_) => return Err(std::io::Error::new(ErrorKind::Other, "Unable to parse command string")),
  };

  println!("Command: {:?}", command_str);
  if !command_str.contains("cmpct") {
      return Err(std::io::Error::new(ErrorKind::Other, "Incorrect command string"));
  }
  
  return Ok(command_str);
}

