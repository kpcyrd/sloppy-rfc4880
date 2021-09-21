use sloppy_rfc4880::errors::*;
use std::fs;
use std::env;
use std::io::{self, Read};
use std::path::PathBuf;

fn find_free_num(prefix: &str, ctr: &mut usize) -> PathBuf {
    loop {
        let path = PathBuf::from(format!("{}{}", prefix, ctr));

        if !path.exists() {
            return path;
        } else {
            *ctr += 1;
        }
    }
}

fn main() -> Result<()> {
    env_logger::init();

    let prefix = env::args().nth(1)
        .context("Missing prefix")?;

    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf)
        .context("read_to_end")?;
    let total = buf.len();

    let mut ctr = 0;
    let mut parser = sloppy_rfc4880::Parser::new(buf.as_slice());

    let mut old = 0;
    loop {
        if parser.next().is_none() {
            break;
        }

        let path = find_free_num(&prefix, &mut ctr);

        let remaining = parser.inner().len();
        let new = total - remaining;

        let range = old..new;
        info!("Dumping {:?} into {:?}, remaining={:?}", range, path, remaining);

        fs::write(path, &buf[range])
            .context("Failed to write")?;

        old = new;
    }

    Ok(())
}
