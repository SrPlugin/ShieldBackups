//! Una `Identity` contiene una clave privada age. Tampoco puede imprimirse.

fn main() {
    let id = sb_crypto::Identity::generate();
    println!("{id:?}");
    println!("{id}");
}
