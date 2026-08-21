//! El prefijo interno del bucket: ponerlo y quitarlo.
//!
//! [`R2Config::clave`](crate::config::R2Config::clave) añade el prefijo a la
//! clave que manda el núcleo. Este módulo hace el camino de vuelta, que es el
//! que usa `List`: el usuario nunca escribió el prefijo al pedir el backup, y
//! verlo aparecer en los resultados haría que la clave que le devolvemos no
//! sirviera para pedir ese mismo artefacto.
//!
//! Vive aparte y sin red porque el caso que importa —la coincidencia parcial—
//! no se ve mirando el código y solo se manifiesta con ciertos nombres de
//! prefijo.

/// Quita `prefijo` del principio de `clave`.
///
/// El prefijo se compara **por segmento completo**: `equipo` no es prefijo de
/// `equipo2/x.age`, aunque lo sea como texto. Recortarlo a ciegas devolvería
/// `2/x.age`, una clave que no existe y que el núcleo intentaría descargar.
///
/// Una clave que no está bajo el prefijo se devuelve tal cual: en un bucket
/// compartido hay objetos que no son de este shieldbk, y mutilarlos sería peor
/// que dejarlos.
#[must_use]
pub fn sin_prefijo(clave: &str, prefijo: &str) -> String {
    // Las barras de los extremos son ruido: `R2Config` ya las quita al
    // normalizar, pero esta función también la llaman los tests y el preflight
    // con lo que tengan a mano.
    let prefijo = prefijo.trim_matches('/');
    if prefijo.is_empty() {
        return clave.to_string();
    }
    // El `strip_prefix('/')` encadenado es la comprobación de segmento: sin él,
    // `equipo` se comería el principio de `equipo2/x.age`. Si no hay barra
    // detrás, la clave no está dentro del prefijo y se devuelve intacta.
    clave
        .strip_prefix(prefijo)
        .and_then(|resto| resto.strip_prefix('/'))
        .unwrap_or(clave)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quita_el_prefijo_de_las_claves_devueltas() {
        // El usuario configuró un prefijo; no debe verlo en los resultados,
        // porque no lo escribió al pedir el backup.
        assert_eq!(
            sin_prefijo("equipo/backups/x.age", "equipo/backups"),
            "x.age"
        );
    }

    #[test]
    fn sin_prefijo_configurado_la_clave_no_cambia() {
        assert_eq!(sin_prefijo("x.age", ""), "x.age");
    }

    #[test]
    fn una_clave_que_no_empieza_por_el_prefijo_se_deja_igual() {
        // Objetos ajenos a este shieldbk que compartan bucket.
        assert_eq!(sin_prefijo("otra/x.age", "equipo"), "otra/x.age");
    }

    #[test]
    fn la_barra_sobrante_del_prefijo_no_estorba() {
        assert_eq!(sin_prefijo("equipo/x.age", "equipo/"), "x.age");
    }

    #[test]
    fn un_prefijo_que_coincide_parcialmente_no_se_recorta() {
        // «equipo2/x» no está dentro de «equipo»: recortarlo daría «2/x».
        assert_eq!(sin_prefijo("equipo2/x.age", "equipo"), "equipo2/x.age");
    }

    #[test]
    fn la_ida_y_vuelta_con_el_prefijo_es_estable() {
        // clave() añade el prefijo, sin_prefijo() lo quita: deben cancelarse.
        for original in ["x.age", "a/b/c.age", "..raro.age", ".oculto"] {
            let completa = format!("equipo/backups/{original}");
            assert_eq!(sin_prefijo(&completa, "equipo/backups"), original);
        }
    }
}
