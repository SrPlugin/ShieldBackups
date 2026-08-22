//! Guarantees checked by the *absence* of compilation.
//!
//! `Secret<T>` and `Identity` deliberately implement neither `Debug` nor
//! `Display`: trying to print a credential must be a compile error, not a log
//! line. An ordinary test cannot verify that — it can only run code that does
//! compile.
//!
//! `trybuild` compiles every file under `tests/ui/` and requires it to fail
//! with exactly the error recorded in its `.stderr`. If someone were to add
//! `#[derive(Debug)]` to either type, this test would go red.
//!
//! To regenerate the `.stderr` files after a legitimate change:
//!
//! ```sh
//! TRYBUILD=overwrite cargo test -p sb-crypto --test compile_fail
//! ```

#[test]
fn printing_a_credential_does_not_compile() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
