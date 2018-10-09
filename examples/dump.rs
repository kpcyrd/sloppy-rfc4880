extern crate sloppy_rfc4880;
extern crate env_logger;

use std::io::{self, Read};

fn main() {
    env_logger::init();

    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf).expect("read_to_end");

    for x in sloppy_rfc4880::Parser::new(buf.as_slice()) {
        println!("{:?}", x);
    }
}
