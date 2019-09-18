all: clippy build test

build:
	cargo build --verbose --all

test:
	cargo test --verbose --all

clippy:
	cargo clippy --all --all-targets --all-features -- -D warnings

