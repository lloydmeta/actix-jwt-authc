docs-render:
	RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --no-deps --all-features --open
