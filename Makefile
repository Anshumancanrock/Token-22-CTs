.PHONY: build-sbf test report lint fixtures screenshot

# The CPI Guard tests load the agent program from target/deploy.
build-sbf:
	cargo build-sbf --manifest-path programs/remit-agent/Cargo.toml

test: build-sbf
	cargo test --workspace

# Transactions, bytes and compute units per flow (the README table).
report: build-sbf
	cargo test -p remit --test cost_report -- --nocapture

lint:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings

# Re-download the mainnet spl-record program used for the U256 range proof.
fixtures:
	solana program dump -um recr1L3PCGKLbckBqMNcJhuuyU1zgo8nBhfLVsJNwr5 fixtures/spl_record.so

# Re-render docs/tests-passing.png from a real `make test` run (Linux `script`, python3-pil).
screenshot: build-sbf
	TERM=xterm-256color script -qfec "make --no-print-directory test" target/make-test.log > /dev/null
	python3 scripts/screenshot.py target/make-test.log docs/tests-passing.png
