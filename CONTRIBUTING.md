# Contributing to Sig**NET**

Thank you for contributing to **Sig**[**NET**]! All changes must satisfy the following security and engineering gates before merge:

1. **Zero Unsafe Code:** `#![forbid(unsafe_code)]` is enforced across the entire crate.
2. **Formatting:** `cargo fmt --all -- --check` must pass with `0` diff lines.
3. **Static Analysis:** `cargo clippy --all-targets -- -D warnings` must pass with `0` warnings.
4. **Cryptographic & Property Tests:** `cargo test` (including `proptest!` capability token tamper & attenuation suites) must pass 100%.
5. **Sterile Fixtures:** Use only RFC 5737 / RFC 2606 / synthetic fixtures in all tests and documentation.
