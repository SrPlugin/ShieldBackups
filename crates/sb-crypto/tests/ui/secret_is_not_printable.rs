//! A `Secret` cannot be printed. If this file ever compiled, the central
//! guarantee of `Secret<T>` would be broken and a credential could end up in a
//! log.

fn main() {
    let s = sb_crypto::Secret::new(String::from("hunter2"));
    println!("{s:?}");
    println!("{s}");
}
