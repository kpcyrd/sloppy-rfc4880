#![warn(unused_extern_crates)]
#[macro_use]
extern crate log;
#[macro_use]
extern crate failure;

use std::io::prelude::*;

pub mod armor;
pub mod errors;
mod encoding;
pub mod packet;
pub use packet::Tag;
pub mod signature;
pub use signature::Signature;


pub struct Parser<R: Read> {
    r: R,
    max_alloc: Option<usize>,
}

impl<R: Read> Parser<R> {
    pub fn new(r: R) -> Parser<R> {
        Parser {
            r,
            max_alloc: None,
        }
    }

    pub fn with_max_alloc(r: R, max_alloc: usize) -> Parser<R> {
        Parser {
            r,
            max_alloc: Some(max_alloc),
        }
    }

    pub fn inner(&self) -> &R {
        &self.r
    }
}

impl<R: Read> Iterator for Parser<R> {
    type Item = (Tag, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        let mut packet_body = Vec::new();
        let tag = packet::read(&mut self.r, &mut packet_body, &self.max_alloc);
        debug!("Received tag: {:?}", tag);

        match tag {
            Ok(tag) => Some((tag, packet_body)),
            _ => None,
        }
    }
}


#[cfg(test)]
mod tests {
    use armor::read_armored;
    use std::io::BufReader;
    use super::*;

    #[test]
    fn extract_userid_from_pubkey() {
        let key = include_bytes!("../data/hans_acker.asc");
        let key = read_armored(&mut BufReader::new(&key[..])).expect("read_armored");

        for (tag, body) in Parser::new(key.as_slice()) {
            println!("{:?}: {:?}", tag, body);
            if tag == Tag::UserID {
                let body = String::from_utf8(body).expect("invalid utf8");
                println!("UserID: {:?}", body);
                assert_eq!("Hans Acker (example comment) <hans.acker@example.com>", body);
                return;
            }
        }

        unreachable!("UserID wasn't found");
    }

    #[test]
    fn extract_userid_from_pubkey_freebsd() {
        let key = include_bytes!("../data/freebsd.asc");
        let key = read_armored(&mut BufReader::new(&key[..])).expect("read_armored");

        for (tag, body) in Parser::new(key.as_slice()) {
            // println!("{:?}: {:?}", tag, body);
            if tag == Tag::UserID {
                let body = String::from_utf8(body).expect("invalid utf8");
                println!("UserID: {:?}", body);
                assert_eq!("FreeBSD Security Officer <security-officer@FreeBSD.org>", body);
                return;
            }
        }

        unreachable!("UserID wasn't found");
    }

    #[test]
    fn extract_userid_from_pubkey_freebsd_with_alloc_limit() {
        let key = include_bytes!("../data/freebsd.asc");
        let key = read_armored(&mut BufReader::new(&key[..])).expect("read_armored");

        for (tag, body) in Parser::with_max_alloc(key.as_slice(), 1024 * 1024) {
            // println!("{:?}: {:?}", tag, body);
            if tag == Tag::UserID {
                let body = String::from_utf8(body).expect("invalid utf8");
                println!("UserID: {:?}", body);
                assert_eq!("FreeBSD Security Officer <security-officer@FreeBSD.org>", body);
                return;
            }
        }

        unreachable!("UserID wasn't found");
    }

    #[test]
    fn extract_userid_from_pubkey_freebsd_with_tiny_alloc_limit() {
        let key = include_bytes!("../data/freebsd.asc");
        let key = read_armored(&mut BufReader::new(&key[..])).expect("read_armored");

        for (_tag, _body) in Parser::with_max_alloc(key.as_slice(), 3) {
            unreachable!("max alloc didn't work");
        }
    }
}
