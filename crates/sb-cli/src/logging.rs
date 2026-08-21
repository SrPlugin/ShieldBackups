//! La traza, y la única regla que la gobierna: **nunca escribe en stdout**.
//!
//! La salida estándar de `shieldbk` pertenece al resultado. Es lo que permite
//! que `shieldbk --format json backup | jq '.targets[].artifact_key'` funcione,
//! y basta un registro colado ahí para romperlo —no de forma llamativa, sino
//! con un `jq` que falla a las tres de la mañana en un `cron` que llevaba meses
//! funcionando—. Así que el suscriptor se fija a stderr aquí, en un solo sitio,
//! y ningún otro módulo del binario construye uno.

use tracing_subscriber::EnvFilter;

/// Enciende la traza con el nivel que pida `verbosidad`.
///
/// La escala sube desde `warn` porque el silencio es el comportamiento correcto
/// de una herramienta que corre desatendida: un backup que va bien no tiene
/// nada que contar, y un `cron` que recibe un correo por cada línea de `info`
/// acaba filtrado a la papelera junto con los avisos que sí importaban.
///
/// `RUST_LOG`, si está definida, manda sobre `-v`: quien la exporta está
/// pidiendo un control más fino —por módulo— del que cabe en un contador de
/// letras, y sobrescribírsela sería ignorar la petición más específica de las
/// dos.
pub fn iniciar(verbosidad: u8) {
    let por_defecto = match verbosidad {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    let filtro = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(por_defecto));

    // Fallar aquí solo puede significar que alguien ya instaló un suscriptor,
    // y en un binario que arranca una sola vez eso no puede pasar. Que no sea
    // motivo de aborto sí importa: quedarse sin registros es molesto, no poder
    // hacer el backup es grave.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filtro)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
}
