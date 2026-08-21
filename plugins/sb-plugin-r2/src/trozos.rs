//! Trocear un flujo en partes de tamaño uniforme.
//!
//! Vive aparte de la subida porque es la pieza que decide si R2 acepta o
//! rechaza el multipart entero, y porque así se puede probar sin red: los
//! tests de abajo son el contrato.

use tokio::io::{AsyncRead, AsyncReadExt as _};

/// Divide un flujo en partes de exactamente `tamano` bytes, salvo la última.
///
/// **R2 exige que todas las partes salvo la última tengan el mismo tamaño**, a
/// diferencia de S3, que lo tolera. Por eso se rellena cada parte hasta
/// completarla en vez de emitir lo que haya llegado de una lectura: un socket
/// entrega los bytes en trozos arbitrarios, y confiar en ellos produciría
/// partes desiguales que R2 rechaza. El fallo, además, solo aparecería con
/// archivos grandes y en producción.
pub struct Troceador<R> {
    fuente: R,
    tamano: usize,
    /// La fuente ya devolvió un cero: no quedan bytes por leer.
    agotada: bool,
    /// Partes ya entregadas. Distingue el flujo vacío —que sí produce una
    /// parte, vacía— del flujo que acabó justo en un múltiplo del tamaño, que
    /// no debe producir una parte vacía de más.
    entregadas: u64,
    total: u64,
}

impl<R: AsyncRead + Unpin> Troceador<R> {
    /// Un troceador sobre `fuente` que emite partes de `tamano` bytes.
    ///
    /// Un tamaño de cero se eleva a uno: no hay troceado posible con partes
    /// vacías, y la alternativa sería un bucle infinito. La configuración ya
    /// impide llegar aquí con menos de 5 MiB.
    pub fn new(fuente: R, tamano: usize) -> Self {
        Self {
            fuente,
            tamano: tamano.max(1),
            agotada: false,
            entregadas: 0,
            total: 0,
        }
    }

    /// Devuelve la siguiente parte, o `None` al terminar.
    ///
    /// Todas las partes miden `tamano` salvo la última, que puede ser menor.
    /// Un flujo vacío produce una única parte vacía.
    ///
    /// # Errors
    ///
    /// El error de lectura de la fuente, tal cual: el que lo llama sabe qué es
    /// esa fuente y puede decir de dónde vino.
    pub async fn siguiente(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        if self.agotada && self.entregadas > 0 {
            return Ok(None);
        }
        let mut parte = vec![0_u8; self.tamano];
        let mut lleno = 0;
        // El bucle es la clave: una sola lectura devuelve lo que haya llegado
        // al socket, que casi nunca es una parte entera. Se insiste hasta
        // completarla o hasta que la fuente se agote.
        while lleno < self.tamano {
            let leidos = self.fuente.read(&mut parte[lleno..]).await?;
            if leidos == 0 {
                self.agotada = true;
                break;
            }
            lleno += leidos;
        }
        // La última parte se queda corta; el resto no.
        parte.truncate(lleno);
        self.total += como_u64(lleno);

        // Un flujo cuyo tamaño es múltiplo exacto de la parte se agota aquí
        // con cero bytes leídos: eso no es una parte, es el final.
        if lleno == 0 && self.entregadas > 0 {
            return Ok(None);
        }
        self.entregadas += 1;
        Ok(Some(parte))
    }

    /// Bytes leídos de la fuente hasta ahora.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.total
    }
}

/// `usize` a `u64` sin un `as` que clippy tenga que perdonar. En las
/// plataformas que soporta el proyecto la conversión nunca satura.
fn como_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fuente que entrega los bytes de uno en uno: el peor caso posible, y el
    /// que revela si el troceado depende de cómo llegaron los datos.
    struct Goteo(Vec<u8>, usize);
    impl tokio::io::AsyncRead for Goteo {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.1 >= self.0.len() {
                return std::task::Poll::Ready(Ok(()));
            }
            let b = self.0[self.1];
            self.1 += 1;
            buf.put_slice(&[b]);
            std::task::Poll::Ready(Ok(()))
        }
    }

    async fn trocear_todo<R: tokio::io::AsyncRead + Unpin>(r: R, tam: usize) -> Vec<Vec<u8>> {
        let mut t = Troceador::new(r, tam);
        let mut partes = Vec::new();
        while let Some(p) = t.siguiente().await.unwrap() {
            partes.push(p);
        }
        partes
    }

    #[tokio::test]
    async fn trocea_en_partes_del_mismo_tamano_salvo_la_ultima() {
        // La regla de R2: todas iguales menos la última.
        let partes = trocear_todo(&vec![1_u8; 25][..], 10).await;
        assert_eq!(partes.len(), 3);
        assert_eq!(partes[0].len(), 10);
        assert_eq!(partes[1].len(), 10);
        assert_eq!(partes[2].len(), 5);
    }

    #[tokio::test]
    async fn un_flujo_exacto_no_produce_una_parte_vacia() {
        let partes = trocear_todo(&vec![1_u8; 20][..], 10).await;
        assert_eq!(
            partes.len(),
            2,
            "20 bytes en partes de 10 son dos partes, no tres"
        );
    }

    #[tokio::test]
    async fn un_flujo_mas_corto_que_una_parte_produce_una_sola() {
        let partes = trocear_todo(&vec![1_u8; 3][..], 10).await;
        assert_eq!(partes.len(), 1);
        assert_eq!(partes[0].len(), 3);
    }

    #[tokio::test]
    async fn un_flujo_vacio_produce_una_parte_vacia() {
        // Un artefacto de cero bytes no existe (age siempre emite cabecera),
        // pero el troceador no debe romperse si ocurre.
        let partes = trocear_todo(&b""[..], 10).await;
        assert_eq!(partes.len(), 1);
        assert!(partes[0].is_empty());
    }

    #[tokio::test]
    async fn el_contenido_se_conserva_al_trocear() {
        let datos: Vec<u8> = (0..100_u32).map(|i| (i % 251) as u8).collect();
        let partes = trocear_todo(&datos[..], 7).await;
        let recompuesto: Vec<u8> = partes.into_iter().flatten().collect();
        assert_eq!(recompuesto, datos);
    }

    #[tokio::test]
    async fn lecturas_de_un_byte_no_alteran_el_troceado() {
        // Un socket entrega los bytes en trozos arbitrarios. Si el troceado
        // dependiera de eso, R2 rechazaría las partes por tamaño desigual.
        let partes = trocear_todo(Goteo(vec![7_u8; 25], 0), 10).await;
        assert_eq!(
            partes.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![10, 10, 5]
        );
    }

    #[tokio::test]
    async fn el_troceado_de_un_socket_lento_conserva_el_contenido() {
        let datos: Vec<u8> = (0..1000_u32).map(|i| (i % 251) as u8).collect();
        let partes = trocear_todo(Goteo(datos.clone(), 0), 64).await;
        assert_eq!(partes.iter().flatten().copied().collect::<Vec<u8>>(), datos);
        let (ultima, resto) = partes.split_last().unwrap();
        assert!(
            resto.iter().all(|p| p.len() == 64),
            "las intermedias, todas iguales"
        );
        assert!(ultima.len() <= 64);
    }

    #[tokio::test]
    async fn un_error_de_lectura_se_propaga() {
        struct Roto;
        impl tokio::io::AsyncRead for Roto {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                _: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Err(std::io::Error::other("roto")))
            }
        }
        let mut t = Troceador::new(Roto, 10);
        assert!(t.siguiente().await.is_err());
    }

    #[tokio::test]
    async fn cuenta_los_bytes_totales() {
        // El vector se ata a un nombre porque el troceador lo toma prestado y
        // le tiene que sobrevivir al `let`.
        let datos = [1_u8; 25];
        let mut t = Troceador::new(&datos[..], 10);
        while t.siguiente().await.unwrap().is_some() {}
        assert_eq!(t.total(), 25);
    }
}
