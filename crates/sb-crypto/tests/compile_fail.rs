/// Este test documenta una garantía del diseño: imprimir un `Secret` no compila.
/// Se verifica manualmente descomentando la línea de abajo — debe dar
/// "`Secret<String>` doesn't implement `Debug`" (y con `{s}`,
/// "doesn't implement `std::fmt::Display`").
#[test]
fn secret_no_es_imprimible() {
    let s = sb_crypto::Secret::new(String::from("x"));
    // println!("{s:?}");  // <- debe ser un error de compilación
    assert_eq!(s.expose(), "x");
}
