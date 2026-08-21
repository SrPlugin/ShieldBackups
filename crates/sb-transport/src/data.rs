use std::path::{Path, PathBuf};

use tokio::net::UnixStream;

/// Canal por el que fluyen los bytes de un backup.
///
/// # Por qué no lleva TLS
///
/// Es deliberado. Ambos extremos son procesos del mismo usuario en la misma
/// máquina, hablando por un socket dentro de un directorio `0700`. Quien pueda
/// leer ese socket ya *es* ese usuario y tiene acceso directo a las
/// credenciales: cifrar aquí no cambiaría el modelo de amenaza y costaría CPU
/// en el camino caliente, que mueve cientos de gigabytes.
///
/// El plano de control sí va cifrado y autenticado, porque por ahí viajan los
/// secretos y porque su volumen es despreciable.
///
/// El socket se borra al destruirse el canal.
pub struct DataChannel {
    /// Se enlaza con la API de `std` a propósito: `create` es síncrona y debe
    /// poder llamarse antes de que exista un runtime. El listener se registra
    /// en el reactor de tokio solo dentro de `accept`.
    listener: std::os::unix::net::UnixListener,
    path: PathBuf,
}

impl DataChannel {
    /// Crea el canal dentro de `dir`, que se fuerza a permisos `0700`.
    ///
    /// Si ya existe un socket con ese nombre —un plugin que murió sin limpiar—
    /// se elimina antes de enlazar, en vez de fallar con «address in use».
    ///
    /// # Errors
    /// Devuelve error si no se puede crear el directorio, ajustar sus permisos
    /// o enlazar el socket.
    pub fn create(dir: &Path, nombre: &str) -> std::io::Result<Self> {
        use std::os::unix::fs::PermissionsExt;

        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;

        let path = dir.join(format!("{nombre}.sock"));
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        Ok(Self { listener, path })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Espera a que el plugin se conecte.
    ///
    /// **Quien llama debe imponer un tiempo límite.** Un plugin que nunca se
    /// conecta dejaría el backup colgado indefinidamente, y un backup colgado
    /// a las tres de la mañana es peor que uno que falla.
    ///
    /// # Errors
    /// Devuelve error si falla el `accept`.
    pub async fn accept(&self) -> std::io::Result<UnixStream> {
        // Se duplica el descriptor para registrarlo en el reactor sin
        // consumir el listener propio del canal, que sobrevive al `accept`.
        let dup = self.listener.try_clone()?;
        dup.set_nonblocking(true)?;
        let listener = tokio::net::UnixListener::from_std(dup)?;
        let (stream, _) = listener.accept().await?;
        Ok(stream)
    }
}

impl Drop for DataChannel {
    fn drop(&mut self) {
        // Best-effort: si falla, el directorio temporal se lleva el socket.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Lado del plugin: se conecta al canal que creó el núcleo.
///
/// # Errors
/// Devuelve error si el socket no existe o no se puede abrir.
pub async fn connect_data(path: &Path) -> std::io::Result<UnixStream> {
    UnixStream::connect(path).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn el_plugin_escribe_y_el_nucleo_lee() {
        // El sentido del backup: el motor produce, el núcleo consume.
        let dir = tempfile::tempdir().unwrap();
        let canal = DataChannel::create(dir.path(), "dump").unwrap();
        let ruta = canal.path().to_path_buf();

        let plugin = tokio::spawn(async move {
            let mut s = connect_data(&ruta).await.unwrap();
            s.write_all(b"bytes del dump").await.unwrap();
            s.shutdown().await.unwrap();
        });

        let mut stream = canal.accept().await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();

        assert_eq!(buf, b"bytes del dump");
        plugin.await.unwrap();
    }

    #[tokio::test]
    async fn el_nucleo_escribe_y_el_plugin_lee() {
        // El sentido del restore, y el de la subida al destino.
        let dir = tempfile::tempdir().unwrap();
        let canal = DataChannel::create(dir.path(), "put").unwrap();
        let ruta = canal.path().to_path_buf();

        let plugin = tokio::spawn(async move {
            let mut s = connect_data(&ruta).await.unwrap();
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await.unwrap();
            buf
        });

        let mut stream = canal.accept().await.unwrap();
        stream.write_all(b"artefacto cifrado").await.unwrap();
        stream.shutdown().await.unwrap();

        assert_eq!(plugin.await.unwrap(), b"artefacto cifrado");
    }

    #[tokio::test]
    async fn mueve_volumen_sin_corromper_nada() {
        let dir = tempfile::tempdir().unwrap();
        let canal = DataChannel::create(dir.path(), "grande").unwrap();
        let ruta = canal.path().to_path_buf();
        let esperado: Vec<u8> = (0..8_u32 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        let copia = esperado.clone();

        let plugin = tokio::spawn(async move {
            let mut s = connect_data(&ruta).await.unwrap();
            s.write_all(&copia).await.unwrap();
            s.shutdown().await.unwrap();
        });

        let mut stream = canal.accept().await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();

        assert_eq!(buf.len(), esperado.len());
        assert_eq!(buf, esperado);
        plugin.await.unwrap();
    }

    #[tokio::test]
    async fn un_flujo_de_cero_bytes_termina_limpiamente() {
        // Una base de datos vacía sigue produciendo un artefacto válido.
        let dir = tempfile::tempdir().unwrap();
        let canal = DataChannel::create(dir.path(), "vacio").unwrap();
        let ruta = canal.path().to_path_buf();

        let plugin = tokio::spawn(async move {
            let mut s = connect_data(&ruta).await.unwrap();
            s.shutdown().await.unwrap();
        });

        let mut stream = canal.accept().await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();

        assert!(buf.is_empty());
        plugin.await.unwrap();
    }

    #[tokio::test]
    async fn el_cierre_del_escritor_se_ve_como_fin_de_flujo() {
        // Es la señal con la que el núcleo sabe que el dump terminó. Sin ella
        // el backup se quedaría esperando para siempre.
        let dir = tempfile::tempdir().unwrap();
        let canal = DataChannel::create(dir.path(), "eof").unwrap();
        let ruta = canal.path().to_path_buf();

        let plugin = tokio::spawn(async move {
            let mut s = connect_data(&ruta).await.unwrap();
            s.write_all(b"algo").await.unwrap();
            s.shutdown().await.unwrap();
        });

        let mut stream = canal.accept().await.unwrap();
        let mut buf = [0_u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"algo");
        // La siguiente lectura debe devolver 0: fin de flujo, no bloqueo.
        assert_eq!(stream.read(&mut buf).await.unwrap(), 0);
        plugin.await.unwrap();
    }

    #[tokio::test]
    async fn dos_canales_en_el_mismo_directorio_no_se_pisan() {
        // Un backup usa dos a la vez: uno del motor y otro hacia el destino.
        let dir = tempfile::tempdir().unwrap();
        let a = DataChannel::create(dir.path(), "dump").unwrap();
        let b = DataChannel::create(dir.path(), "put").unwrap();
        assert_ne!(a.path(), b.path());

        let ruta_a = a.path().to_path_buf();
        let ruta_b = b.path().to_path_buf();

        let t = tokio::spawn(async move {
            let mut sa = connect_data(&ruta_a).await.unwrap();
            sa.write_all(b"AAA").await.unwrap();
            sa.shutdown().await.unwrap();
            let mut sb = connect_data(&ruta_b).await.unwrap();
            sb.write_all(b"BBB").await.unwrap();
            sb.shutdown().await.unwrap();
        });

        let mut sa = a.accept().await.unwrap();
        let mut va = Vec::new();
        sa.read_to_end(&mut va).await.unwrap();

        let mut sb = b.accept().await.unwrap();
        let mut vb = Vec::new();
        sb.read_to_end(&mut vb).await.unwrap();

        assert_eq!(va, b"AAA");
        assert_eq!(vb, b"BBB");
        t.await.unwrap();
    }

    #[test]
    fn el_directorio_del_socket_es_privado() {
        // La única defensa del canal de datos: nadie más puede abrirlo.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let canal = DataChannel::create(dir.path(), "perm").unwrap();
        let modo = std::fs::metadata(canal.path().parent().unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            modo & 0o777,
            0o700,
            "el directorio debe ser accesible solo por el propietario"
        );
    }

    #[test]
    fn el_socket_se_borra_al_destruir_el_canal() {
        let dir = tempfile::tempdir().unwrap();
        let ruta = {
            let canal = DataChannel::create(dir.path(), "efimero").unwrap();
            canal.path().to_path_buf()
        };
        assert!(!ruta.exists(), "el socket no debe sobrevivir al canal");
    }

    #[test]
    fn se_puede_crear_sobre_un_socket_huerfano() {
        // Un plugin que murió sin limpiar deja el socket atrás. El backup
        // siguiente debe funcionar igual, no fallar con "address in use".
        let dir = tempfile::tempdir().unwrap();
        let primero = DataChannel::create(dir.path(), "reuso").unwrap();
        let ruta = primero.path().to_path_buf();
        std::mem::forget(primero); // simula una muerte sin limpieza

        assert!(ruta.exists(), "el socket huérfano sigue ahí");
        let segundo = DataChannel::create(dir.path(), "reuso").unwrap();
        assert_eq!(segundo.path(), ruta);
    }

    #[tokio::test]
    async fn conectar_a_un_canal_inexistente_da_error() {
        assert!(
            connect_data(std::path::Path::new("/tmp/no-existe-shieldbk-data.sock"))
                .await
                .is_err()
        );
    }
}
