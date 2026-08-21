//! Generador de bytes reproducibles.

/// Genera `n` bytes reproducibles a partir de una semilla.
///
/// Usa xorshift64: no es criptográfico ni lo pretende. Lo que hace falta es que
/// sea determinista, rápido y que **no comprima trivialmente**, para que los
/// tests del pipeline midan algo real en vez de pasar por accidente.
///
/// Un prefijo del flujo es prefijo exacto del flujo más largo con la misma
/// semilla: pedir 1 KiB y pedir 1 MiB dan el mismo comienzo.
pub fn datos_deterministas(semilla: u64, n: usize) -> impl Iterator<Item = u8> {
    // El `| 1` evita el único estado absorbente de xorshift64: el cero, que se
    // repetiría a sí mismo para siempre.
    let mut estado = semilla.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..n).map(move |_| {
        estado ^= estado << 13;
        estado ^= estado >> 7;
        estado ^= estado << 17;
        // `to_le_bytes()[0]` en vez de `as u8`: es el mismo byte bajo, pero sin
        // un cast con truncamiento que clippy pedantic tenga que perdonar.
        estado.to_le_bytes()[0]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_misma_semilla_produce_los_mismos_bytes() {
        // Sin esto, un test del núcleo no podría comparar lo restaurado con lo
        // que el motor produjo.
        let a: Vec<u8> = datos_deterministas(42, 1000).collect();
        let b: Vec<u8> = datos_deterministas(42, 1000).collect();
        assert_eq!(a, b);
    }

    #[test]
    fn semillas_distintas_producen_datos_distintos() {
        let a: Vec<u8> = datos_deterministas(1, 1000).collect();
        let b: Vec<u8> = datos_deterministas(2, 1000).collect();
        assert_ne!(a, b);
    }

    #[test]
    fn produce_exactamente_los_bytes_pedidos() {
        assert_eq!(datos_deterministas(7, 12_345).count(), 12_345);
        assert_eq!(datos_deterministas(7, 0).count(), 0);
        assert_eq!(datos_deterministas(7, 1).count(), 1);
    }

    #[test]
    fn los_datos_cubren_casi_todo_el_rango_de_byte() {
        // Un generador que devolviera ceros haría que los tests de compresión
        // del pipeline pasaran por la razón equivocada.
        let datos: Vec<u8> = datos_deterministas(3, 10_000).collect();
        let distintos: std::collections::HashSet<_> = datos.iter().collect();
        assert!(
            distintos.len() > 200,
            "solo {} valores distintos",
            distintos.len()
        );
    }

    #[test]
    fn un_prefijo_es_prefijo_del_flujo_mas_largo() {
        // Permite que un test pida 1 KB y otro 1 MB de la misma semilla y que
        // el primero sea el comienzo exacto del segundo.
        let corto: Vec<u8> = datos_deterministas(9, 100).collect();
        let largo: Vec<u8> = datos_deterministas(9, 1000).collect();
        assert_eq!(corto, largo[..100]);
    }
}
