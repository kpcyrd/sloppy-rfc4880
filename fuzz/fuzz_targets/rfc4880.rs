#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate sloppy_rfc4880;

fuzz_target!(|data: &[u8]| {
    for _ in sloppy_rfc4880::Parser::new(data) {
        //
    }
});
