extern crate sloppy_rfc4880;
extern crate env_logger;
#[macro_use] extern crate log;

use std::io::{self, Read};

fn main() {
    env_logger::init();

    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf).expect("read_to_end");

    let mut parser = sloppy_rfc4880::Parser::new(buf.as_slice());

    loop {
        match parser.next() {
            Some(x) => println!("{:?}", x),
            None => break,
        }
        info!("Remaining: {:?}", parser.inner().len());
    }
}
