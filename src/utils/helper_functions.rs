use sha2::{Sha256, Digest};
use tokio::net::TcpStream;
use rand::{Rng, thread_rng};

pub fn get_u64_from_byte_array(data: &mut [u8]) -> Result<u64, &'static str> {
    if data.len() < 8 {
      return Err("Byte array size must be at least 8");
    }

    data.copy_within(8..data.len(), 0);
    let mut number: [u8; 8] = [0; 8];
    number.copy_from_slice(&data[..8]);
    let value = u64::from_le_bytes(number);
    return Ok(value)
}

pub fn get_u32_from_byte_array(data: &mut [u8]) -> Result<u32, &'static str> {
    if data.len() < 4 {
      return Err("Byte array size must be at least 4");
    }

    let mut number: [u8; 4] = [0; 4];
    number.copy_from_slice(&data[..4]);
    let value = u32::from_le_bytes(number);
    data.copy_within(4..data.len(), 0);
    return Ok(value)
}

pub fn calculate_checksum(data_buffer: &[u8]) -> [u8; 4] {
  let mut hasher_1 = Sha256::new();
  hasher_1.update(data_buffer);
  let first_hash = hasher_1.finalize();
  let mut hasher_2 = Sha256::new();
  hasher_2.update(first_hash);
  let second_hash = hasher_2.finalize();
  let mut buf = [0u8; 4];
  buf.clone_from_slice(&second_hash[..4]);
  return buf
}

pub async fn tcp_handshake(ip: &str)->Result<TcpStream, std::io::Error>{
  match TcpStream::connect(ip).await{
    Ok(tcp) => return Ok(tcp),
    Err(err) => return Err(err),
  };
}

pub fn generate_nonce() -> u64 {
  let mut rng = thread_rng(); // random gen
  rng.gen::<u64>()
}
