#![cfg_attr(feature="cargo-clippy", deny(clippy_pedantic))]
#![cfg_attr(feature="cargo-clippy", allow(missing_docs_in_private_items, similar_names, print_stdout))]
#![deny(missing_debug_implementations, missing_copy_implementations, trivial_casts, trivial_numeric_casts)]
#![deny(unsafe_code, unused_import_braces, unused_qualifications)]

extern crate crypto;
extern crate base64;
extern crate rand;
#[macro_use]
extern crate hyper;
extern crate hyper_tls;
extern crate futures;
extern crate tokio_core;
extern crate serde;
extern crate serde_json;
extern crate url;
#[macro_use]
extern crate serde_derive;

use url::form_urlencoded;

use std::io;
use futures::{future, Future, Stream};
use hyper::Error;
use tokio_core::reactor::Core;
use hyper::Method;
use hyper::client::{Client, Request};
use hyper::header::{ContentLength, ContentType};
use hyper::header::{self, qitem};
use hyper::mime;
use rand::{thread_rng, Rng};
use crypto::{ symmetriccipher, buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer };
use crypto::md5::Md5;
use crypto::digest::Digest;
use hyper_tls::HttpsConnector;

header! { (XRequestedWith, "X-Requested-With") => [String] }

fn main() {
    let password = generate_password();
    let data = encrypt("test", &password);

    let mut event_loop = Core::new().unwrap();
    let handle = event_loop.handle();
    let client = Client::configure()
        .connector(HttpsConnector::new(4,&handle).unwrap())
        .build(&handle);

    let form_data: String = form_urlencoded::Serializer::new(String::new())
        .append_pair("data", &data)
        .append_pair("has_manual_pass", "false")
        .append_pair("duration_hours", "0")
        .append_pair("data_type", "T")
        .append_pair("dont_ask", "false")
        .append_pair("notify_email", "")
        .append_pair("notify_ref", "")
        .finish();

    let uri = "https://privnote.com/legacy/".parse().unwrap();
    let mut req = Request::new(Method::Post, uri);
    req.headers_mut().set(ContentType::form_url_encoded());
    req.headers_mut().set(ContentLength(form_data.len() as u64));
    req.headers_mut().set(header::UserAgent::new("privnoters (https://github.com/daveallie/privnoters)"));
    req.headers_mut().set(header::Accept(vec![qitem(mime::APPLICATION_JSON), qitem(mime::STAR_STAR)]));
    req.headers_mut().set(header::Connection::keep_alive());
    req.headers_mut().set(XRequestedWith("XMLHttpRequest".to_string()));
    req.set_body(form_data);

    let work = client.request(req).and_then(|res| {
        res.body().fold(Vec::new(), |mut v, chunk| {
            v.extend(&chunk[..]);
            future::ok::<_, Error>(v)
        }).and_then(|chunks| {
            let s = String::from_utf8(chunks).unwrap();
            future::ok::<_, Error>(s)
        })
    });

    let body = event_loop.run(work).unwrap();

    let priv_res: PrivnoteRepsonse = serde_json::from_slice(body.as_bytes()).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            e
        )
    }).unwrap();

    println!("{}#{}", priv_res.note_link, password);
}

fn encrypt(data: &str, password: &str) -> String {
    let salt = generate_salt();
    let salt_block: Vec<u8> = [[83, 97, 108, 116, 101, 100, 95, 95], salt].concat();

    let key = key_from_password(&password.as_bytes(), &salt);
    let cipher_blocks: Vec<u8> = encrypt_block(data.as_bytes(), &key.key, &key.iv).ok().unwrap();
    let mut bytes = salt_block;
    bytes.extend(cipher_blocks);
    base64::encode(&bytes)
}

fn generate_password() -> String {
    let mut rng = thread_rng();
    rng.gen_ascii_chars().take(9).collect()
}

fn encrypt_block(block: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut encryptor: Box<symmetriccipher::Encryptor> = aes::cbc_encryptor(
        aes::KeySize::KeySize256,
        key,
        iv,
        blockmodes::PkcsPadding
    );

    let mut final_result: Vec<u8> = vec![];
    let mut buffer = [0; 4096];
    let mut read_buffer = buffer::RefReadBuffer::new(block);
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = try!(encryptor.encrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend_from_slice(write_buffer.take_read_buffer().take_remaining());
        match result {
            buffer::BufferResult::BufferUnderflow => break,
            buffer::BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}

fn generate_salt() -> [u8; 8] {
    let mut rng = thread_rng();
    let nums: Vec<u8> = rng.gen_iter().take(8).collect();

    let mut salt = [0_u8; 8];
    salt.clone_from_slice(&nums[..8]);
    salt
}

struct Key {
    key: [u8; 32],
    iv: [u8; 16],
}

#[derive(Deserialize, Debug)]
struct PrivnoteRepsonse {
    note_link: String,
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
    let mut key = [0_u8; 32];
    let mut iv = [0_u8; 16];
    key.clone_from_slice(&result[0..32]);
    iv.clone_from_slice(&result[32..48]);

    Key {
        key,
        iv,
    }
}
