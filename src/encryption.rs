use base64;
use crypto::{symmetriccipher, buffer, aes, blockmodes};
use crypto::buffer::{ReadBuffer, WriteBuffer};
use crypto::digest::Digest;
use crypto::md5::Md5;
use rand::{thread_rng, Rng};

pub fn encrypt(data: &str, password: &str) -> Result<String, symmetriccipher::SymmetricCipherError> {
    let salt = generate_salt();
    let salt_block: Vec<u8> = [[83, 97, 108, 116, 101, 100, 95, 95], salt].concat();

    let key = key_from_password(password.as_bytes(), &salt);
    let cipher_blocks: Vec<u8> = encrypt_block(data.as_bytes(), &key.key, &key.iv)?;
    let mut bytes = salt_block;
    bytes.extend(cipher_blocks);
    Ok(base64::encode(&bytes))
}

fn encrypt_block(block: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut encryptor: Box<symmetriccipher::Encryptor> =
        aes::cbc_encryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

    let mut final_result: Vec<u8> = vec![];
    let mut buffer = [0; 4096];
    let mut read_buffer = buffer::RefReadBuffer::new(block);
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)?;
        final_result.extend_from_slice(write_buffer.take_read_buffer().take_remaining());
        match result {
            buffer::BufferResult::BufferUnderflow => break,
            buffer::BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}

fn generate_salt() -> [u8; 8] {
    let mut rng = thread_rng();
    let nums: Vec<u8> = rng.gen_iter().take(8).collect();

    let mut salt = [0_u8; 8];
    salt.clone_from_slice(&nums);
    salt
}

struct Key {
    key: [u8; 32],
    iv: [u8; 16],
}

fn key_from_password(password: &[u8], salt: &[u8; 8]) -> Key {
    let mut md5 = Md5::new();
    let mut hashes = [[0_u8; 16]; 3];
    let data0: Vec<u8> = [password, salt].concat();

    md5.input(&data0);
    md5.result(&mut hashes[0]);
    md5.reset();

    let mut data = hashes[0].to_vec();
    data.extend(&data0);
    md5.input(&data);
    md5.result(&mut hashes[1]);
    md5.reset();

    let mut data = hashes[1].to_vec();
    data.extend(&data0);
    md5.input(&data);
    md5.result(&mut hashes[2]);

    let result: Vec<u8> = hashes.iter().flat_map(|s| s.iter().cloned()).collect();
    let (key_slice, iv_slice) = result.split_at(32);
    let mut key = [0_u8; 32];
    let mut iv = [0_u8; 16];
    key.clone_from_slice(key_slice);
    iv.clone_from_slice(iv_slice);

    Key { key, iv }
}
