#![cfg_attr(feature="cargo-clippy", deny(clippy, clippy_restriction, clippy_pedantic, clippy_style,
                                         clippy_complexity, clippy_correctness, clippy_perf, clippy_nursery))]
#![cfg_attr(feature="cargo-clippy", allow(missing_docs_in_private_items, print_stdout))]
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

mod request;
mod encryption;

use rand::{thread_rng, Rng};
use std::error::Error;
use std::io::{self, Read};

fn main() {
    let data = get_data().expect("Failed to read data from stdin");
    if data.is_empty() {
        panic!("Data to be encrypted is empty");
    }

    let password = generate_password();
    let enc_data = encryption::encrypt(&data, &password).expect("Failed to encrypt data");
    let body = request::post_privnote_data(&enc_data).expect("Failed to post encrypted data to privnote");

    let priv_res: PrivnoteRepsonse =
        serde_json::from_slice(body.as_bytes()).expect("Failed to parse privnote response to JSON");

    println!("{}#{}", priv_res.note_link, password);
}

fn get_data() -> Result<String, Box<Error>> {
    let mut buffer = String::new();
    let stdin = io::stdin();
    let mut handle = stdin.lock();

    handle.read_to_string(&mut buffer)?;
    Ok(buffer)
}

fn generate_password() -> String {
    let mut rng = thread_rng();
    rng.gen_ascii_chars().take(9).collect()
}

#[derive(Deserialize, Debug)]
struct PrivnoteRepsonse {
    note_link: String,
}
