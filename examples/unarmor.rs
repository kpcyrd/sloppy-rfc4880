use sloppy_rfc4880::errors::*;
use std::io::{self, prelude::*};

fn main() -> Result<()> {
    env_logger::init();

    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf)
        .context("read_to_end")?;

    let key = sloppy_rfc4880::armor::read_armored(&mut buf.as_slice())
        .context("read_armored")?;
    io::stdout().write_all(&key)
        .context("write_all")?;

    Ok(())
}
