//! `shieldbk`: la cara visible de `ShieldBackups`.
//!
//! Este archivo no hace nada más que arrancar. Interpretar los argumentos vive
//! en [`cli`], decidir qué se ejecuta en [`commands`], y cómo se cuenta el
//! resultado en [`output`]. Aquí solo queda el orden en que se encadenan y la
//! única decisión que no cabe en ninguno de los tres: **con qué código de
//! salida termina el proceso**.
//!
//! Ese código es lo que convierte la herramienta en algo automatizable. Un
//! `cron` que solo distinga «cero» de «no cero» acaba mandando el mismo aviso
//! cuando falta una coma en el TOML que cuando la base de datos no responde,
//! así que [`error::CliError`] separa los tres casos y esta función los
//! traduce.

mod artifacts;
mod cli;
mod commands;
mod context;
mod error;
mod logging;
mod output;
mod paths;
mod plugins;

use std::process::ExitCode;

use clap::Parser as _;

use crate::cli::Cli;
use crate::output::Salida;

fn main() -> ExitCode {
    let cli = Cli::parse();

    // La traza se enciende antes que nada: los fallos de carga de la
    // configuración también merecen contexto cuando alguien pide `-v`.
    logging::iniciar(cli.verbose);

    let salida = Salida::new(cli.format);

    // El runtime se construye aquí y no con `#[tokio::main]` para que el
    // código de salida siga siendo lo último que decide este archivo: una
    // macro que envuelva `main` obligaría a devolver el error por `Termination`
    // y a renunciar a distinguir sus tres clases.
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(fuente) => {
            let error = error::CliError::operacion(format!(
                "no se pudo arrancar el runtime asíncrono: {fuente}"
            ));
            salida.fallo(&error);
            return ExitCode::from(u8::try_from(error.codigo()).unwrap_or(1));
        }
    };

    match runtime.block_on(commands::ejecutar(&cli)) {
        // Un informe puede traer un fallo dentro: es lo que distingue «no pude
        // hacerlo» de «lo hice y esto es lo que encontré».
        Ok(informe) => {
            salida.emitir(&informe);
            ExitCode::from(u8::try_from(informe.codigo()).unwrap_or(1))
        }
        Err(error) => {
            salida.fallo(&error);
            ExitCode::from(u8::try_from(error.codigo()).unwrap_or(1))
        }
    }
}
