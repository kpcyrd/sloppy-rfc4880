extern crate sloppy_rfc4880;
extern crate env_logger;
extern crate bytes;
#[macro_use] extern crate log;

use std::io::{self, Read};
use sloppy_rfc4880::{Tag, signature};

fn main() {
    env_logger::init();

    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf).expect("read_to_end");

    let mut parser = sloppy_rfc4880::Parser::new(buf.as_slice());

    loop {
        match parser.next() {
            Some((tag, body)) => {
                let body = bytes::Bytes::from(body.clone());
                println!("{:?}: {:?}", tag, body);
                if tag == Tag::Signature {
                    let issuer = signature::parse(&*body).expect("signature::parse");
                    println!("\tissuer: {:?}", issuer);
                }
            },
            None => break,
        }
        info!("Remaining: {:?}", parser.inner().len());
    }
}
