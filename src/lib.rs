#![warn(unused_extern_crates)]
#[macro_use]
extern crate log;
extern crate byteorder;
extern crate base64;
#[macro_use]
extern crate failure;

use std::io::prelude::*;

pub mod armor;
pub mod errors;
mod encoding;
pub mod packet;
pub use packet::Tag;


pub struct Parser<R: Read> {
    r: R,
}

impl<R: Read> Parser<R> {
    pub fn new(r: R) -> Parser<R> {
        Parser {
            r,
        }
    }
}

impl<R: Read> Iterator for Parser<R> {
    type Item = (Tag, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        let mut packet_body = Vec::new();
        let tag = packet::read(&mut self.r, &mut packet_body);

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
        let key = String::from(r#"-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2
Foo: bar

mQENBFu6q90BCADgD7Q9aH5683yt7hzPktDkAUNAZJHwYhUNeyGK43frPyDRWQmq
N+oXTfiYWLQN+d7KNBTnF9uwyBdaLM7SH44lLNYo8W09mVM2eK+wt19uf5HYNgAE
8la45QLo/ce9CQVe1a4oXNWq6l0FOY7M+wLe+G2wMwz8RXGgwd/qQp4/PB5YpUhx
nAnzClxvwymrL6BQXsRcKSMSD5bIzIv95n105CvW5Hql7JR9zgOR+gHqVOH8HBUc
ZxMumrTM6aKLgAhgM8Sn36gCFOfjlG1b1OFLZhUtgro/nnEOmAurRsCZy8M5h8QM
FpZChIH8kgHs90F/CCvGjMq3qvWcH8ZsPUizABEBAAG0NUhhbnMgQWNrZXIgKGV4
YW1wbGUgY29tbWVudCkgPGhhbnMuYWNrZXJAZXhhbXBsZS5jb20+iQFOBBMBCAA4
FiEEyzeO1eEwbB03hcqBM00IodGdlj8FAlu6q90CGwMFCwkIBwIGFQgJCgsCBBYC
AwECHgECF4AACgkQM00IodGdlj/AJQgAjmk+iP5b7Jt7+f+lU4Oprlf3f3DG/uh5
Ge6MjV7cvtxlhZJRD5hxGt9RwwnEp61TBSbrem288pM89ilQfTNe0wUr9OzwWzh/
8Ngl5iWnD2ah3Mpi5R1V/YMNf2cnwVjqNvfkRHdNc43pZOkC2GoiTUn0QY0UBpOW
ZMN3//ANi6ZtiK/L0IZQND/gKvOzu/4tfaJeBl26T3cVYj53p3G3jhlb92vVa8SR
uL3S3bzd1h5snDgU1uXHmNHGbhkEc4KUneQ0V9/bdZrg6OzFAfM1ghgfoId+YpQH
er9L26ISL3QF58wdEXfIdHYEmMlANjBMO2cUlQXgONuCgkMuY7GBmrkBDQRbuqvd
AQgA41jqCumCxYV0NdSYNnTSSDRyd69dOUYCAPT80iZ739s7KKJS9X9KVfGmDjfi
u2RcfR/KYj53HoyOm4Pm/+ONN8De4ktzXpIpJxGC+O8NBvd9vkboAS6qnCjK7KVE
r91ymxxVKp2dzZvVfpIjWVZR5i2EAvS5vw8UK4gL8ALH+S9leJFZrQWcgyoJOJzH
Rzr9pesX2HvdgcNG1O6QUArlsnsTnqpi/hu7tQa8tifBpWDeArOA23Y2DgeehdDF
lSU/8KD4J+AkFrWWlcTaMsvSChXQkCHEMRIcSOfXtdpX5KJSE7UBQdD1opm+mR79
VeHnuJAAVZZtUZmJA7pjdKykYQARAQABiQE2BBgBCAAgFiEEyzeO1eEwbB03hcqB
M00IodGdlj8FAlu6q90CGwwACgkQM00IodGdlj8bMAf+Lq3Qive4vcrCTT4IgvVj
arOACdcbtt5RhVBTimT19rDWNH+m+PfPjo3FSlBj5cm70KAXUS2LBFFxhakTZ/Mq
cQroWZpVbBxj4kipEVVJZFdUZQaDERJql0xYGOQrNMQ4JGqJ84BRrtOExjSqo41K
hAhNe+bwPGH9/Igiixc4tH07xa7TOy4MyJv/6gpbHy/lW1hqpCAgM5fT/im5/6QF
k0tED6vIuc54IWiOmwCnjZiQnJ8uCwEu+cuJ5Exwy9CNERLp5v0y4eG+0E+at9j/
macOg39qf09t53pTqe9dWv5NIi319TeBsKZ2lb0crrQjsbHqk0DAUwgQuoANqLku
vA==
=kRIv
-----END PGP PUBLIC KEY BLOCK-----"#);
        let key = read_armored(&mut BufReader::new(key.as_bytes())).expect("read_armored");

        for (tag, body) in Parser::new(key.as_slice()) {
            println!("{:?}: {:?}", tag, body);
            if tag == Tag::UserID {
                let body = String::from_utf8(body).expect("invalid utf8");
                println!("UserID: {:?}", body);
                assert_eq!("Hans Acker (example comment) <hans.acker@example.com>", body);
                return;
            }
        }

        // UserID wasn't found
        assert!(false);
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

        // UserID wasn't found
        assert!(false);
    }
}
