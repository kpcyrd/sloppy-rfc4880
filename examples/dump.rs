extern crate sloppy_rfc4880;
extern crate env_logger;
extern crate bytes;
#[macro_use] extern crate log;

use std::io::{self, Read};
use sloppy_rfc4880::{Tag, pubkey, signature};

fn main() {
    env_logger::init();

    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf).expect("read_to_end");

    let mut parser = sloppy_rfc4880::Parser::new(buf.as_slice());

    while let Some((tag, body)) = parser.next() {
        let body = bytes::Bytes::from(body.clone());
        println!("{:?}: {:?}", tag, body);
        match tag {
            Tag::PublicKey => {
                let fp = pubkey::fingerprint(&*body);
                println!("\tfingerprint: {:?}", fp);
            },
            Tag::Signature => {
                let issuer = signature::parse(&*body).expect("signature::parse");
                println!("\tissuer: {:?}", issuer);
            },
            _ => (),
        }
        info!("Remaining: {:?}", parser.inner().len());
    }
}
