//! An `Identity` holds an age private key. It cannot be printed either.

fn main() {
    let id = sb_crypto::Identity::generate();
    println!("{id:?}");
    println!("{id}");
}
