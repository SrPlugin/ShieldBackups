use zeroize::Zeroize;

/// Contenedor de un valor sensible.
///
/// No implementa `Debug` ni `Display` a propósito: si algo intenta imprimir un
/// secreto, el resultado debe ser un error de compilación, no una línea de log.
/// El contenido se borra de memoria al destruirse el valor.
///
/// # Qué garantiza y qué no
///
/// Garantiza que una credencial no pueda acabar en un log por accidente, y que
/// el valor que este contenedor posee se borre al destruirse.
///
/// **No** garantiza que ninguna copia sobreviva en memoria. Un `String` que
/// realoca al crecer deja atrás su buffer anterior sin borrar, y clonar un
/// `Secret` crea una asignación nueva e independiente. Construye el valor con
/// su capacidad final siempre que puedas, y no des por hecho más protección de
/// la que hay.
///
/// La comparación con `PartialEq` es de tiempo constante en el contenido, pero
/// devuelve antes si las longitudes difieren: filtra la longitud, no el valor.
/// Es el comportamiento estándar para comparar credenciales.
#[derive(Clone)]
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Único acceso al valor. El nombre es deliberadamente incómodo para que
    /// cada uso sea visible en revisión de código.
    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize + AsRef<[u8]>> PartialEq for Secret<T> {
    fn eq(&self, other: &Self) -> bool {
        let a = self.0.as_ref();
        let b = other.0.as_ref();
        if a.len() != b.len() {
            return false;
        }
        // Comparación sin salida temprana: no filtra por tiempo cuánto prefijo coincide.
        a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }
}

impl<T: Zeroize + AsRef<[u8]>> Eq for Secret<T> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expone_el_valor_solo_al_pedirlo_explicitamente() {
        let s = Secret::new(String::from("hunter2"));
        assert_eq!(s.expose(), "hunter2");
    }

    #[test]
    fn dos_secretos_con_el_mismo_valor_son_iguales() {
        let a = Secret::new(String::from("mismo"));
        let b = Secret::new(String::from("mismo"));
        // `assert!` en vez de `assert_eq!`: este último exigiría `Debug`, que
        // `Secret` no implementa a propósito.
        assert!(a == b);
    }

    #[test]
    fn la_comparacion_es_en_tiempo_constante_para_bytes() {
        // No mide tiempo: verifica que el camino de comparación existe y es correcto.
        let a = Secret::new(vec![1_u8, 2, 3]);
        let b = Secret::new(vec![1_u8, 2, 3]);
        let c = Secret::new(vec![1_u8, 2, 4]);
        assert!(a == b);
        assert!(a != c);
    }

    #[test]
    fn se_puede_clonar() {
        let a = Secret::new(String::from("x"));
        let b = a.clone();
        assert_eq!(b.expose(), "x");
    }
}
