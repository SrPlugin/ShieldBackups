//! Un `Secret` no puede imprimirse. Si este archivo llegara a compilar, la
//! garantía central de `Secret<T>` estaría rota y una credencial podría acabar
//! en un log.

fn main() {
    let s = sb_crypto::Secret::new(String::from("hunter2"));
    println!("{s:?}");
    println!("{s}");
}
