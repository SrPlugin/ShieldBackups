//! Garantías que se comprueban por *ausencia* de compilación.
//!
//! `Secret<T>` e `Identity` no implementan `Debug` ni `Display` a propósito:
//! intentar imprimir una credencial debe ser un error de compilación, no una
//! línea de log. Un test normal no puede verificar eso — solo puede ejecutar
//! código que sí compila.
//!
//! `trybuild` compila cada archivo de `tests/ui/` y exige que falle con
//! exactamente el error registrado en su `.stderr`. Si alguien añadiera
//! `#[derive(Debug)]` a cualquiera de los dos tipos, este test se pondría rojo.
//!
//! Para regenerar los `.stderr` tras un cambio legítimo:
//!
//! ```sh
//! TRYBUILD=overwrite cargo test -p sb-crypto --test compile_fail
//! ```

#[test]
fn imprimir_una_credencial_no_compila() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
