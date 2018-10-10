#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate sloppy_rfc4880;

const MAX_ALLOC: usize = 1024 * 1024 * 100; // 100MiB

fuzz_target!(|data: &[u8]| {
    let mut buf = Vec::new();
    let _ = sloppy_rfc4880::packet::read(&mut &data[..], &mut buf, &Some(MAX_ALLOC));
});
