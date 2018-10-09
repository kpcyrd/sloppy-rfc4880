#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate sloppy_rfc4880;

const MAX_ALLOC: usize = 1024 * 1024 * 100; // 100MiB

fuzz_target!(|data: &[u8]| {
    for _ in sloppy_rfc4880::Parser::with_max_alloc(data, MAX_ALLOC) {
        //
    }
});
