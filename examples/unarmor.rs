extern crate sloppy_rfc4880;
extern crate env_logger;

use std::io::{self, prelude::*};

fn main() {
    env_logger::init();

    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf).expect("read_to_end");

    let key = sloppy_rfc4880::armor::read_armored(&mut buf.as_slice()).expect("read_armored");
    io::stdout().write_all(&key).expect("write_all");
}
