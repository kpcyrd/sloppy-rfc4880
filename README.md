# sloppy-rfc4880 [![Build Status][travis-img]][travis] [![crates.io][crates-img]][crates] [![docs.rs][docs-img]][docs]

[travis-img]:   https://travis-ci.com/kpcyrd/sloppy-rfc4880.svg?branch=master
[travis]:       https://travis-ci.com/kpcyrd/sloppy-rfc4880
[crates-img]:   https://img.shields.io/crates/v/sloppy-rfc4880.svg
[crates]:       https://crates.io/crates/sloppy-rfc4880
[docs-img]:     https://docs.rs/sloppy-rfc4880/badge.svg
[docs]:         https://docs.rs/sloppy-rfc4880

Pure rust parser for RFC-4880 (OpenPGP Message Format). The codebase is heavily
based on the [openpgp] crate, but all crypto code has been removed to keep the
number of dependencies low for project that only need to decode the binary
packet format.

[openpgp]: https://crates.io/crates/openpgp

In addition, the codebase has been hardened to ensure it can handle arbitrary
input without crashing. Also, an optional allocation limit has been added to
avoid OOM on bogus inputs.

# Fuzzing

The codebase was extensively fuzzed using cargo-fuzz and libfuzzer. The corpus
folder has been bootstrapped using a full dump of a pgp keyserver:

```sh
git clone https://github.com/kpcyrd/sloppy-rfc4880
mkdir pgp
cd pgp
wget -c -r -p -e robots=off -N -l1 --cut-dirs=3 -nH http://pgp.key-server.io/dump/2018-10-07/
cd ../sloppy-rfc4880

for x in ../pgp/sks-dump-*; do
    cat "$x" | cargo run --release --example split fuzz/corpus/rfc4880/pgp
    cargo +nightly fuzz cmin --release rfc4880
done
```

You can download a copy of a pre-processed corpus folder from the [release page][0].

[0]: https://github.com/kpcyrd/sloppy-rfc4880/releases

To start fuzzing, run:
```sh
cargo +nightly fuzz run --release rfc4880 -j $(nproc) -- -timeout=240 -rss_limit_mb=500
```

# License

Apache-2.0
