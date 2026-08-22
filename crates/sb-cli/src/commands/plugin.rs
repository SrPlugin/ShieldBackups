//! `shieldbk plugin list | docs <plugin> | verify | lock`.
//!
//! Los cuatro giran alrededor del lockfile, que es lo que separa «un binario
//! que está en el directorio» de «un binario que este sistema autoriza a
//! recibir las credenciales de su base de datos». `lock` da esa autorización,
//! `verify` la comprueba sin ejecutar nada, `list` la enseña y `docs` es el
//! único que arranca un plugin —y solo para preguntarle qué campos acepta—.
//!
//! `docs` **nunca imprime valores**, solo el esquema. La diferencia no es
//! cosmética: el esquema dice que existe un campo `password`, y un comando que
//! imprimiera «lo que hay configurado» lo imprimiría también.

use std::fmt::Write as _;

use sb_core::lockfile::{Lockfile, LockfileError};
use sb_proto::{Field, FieldType};

use crate::context::Contexto;
use crate::error::CliError;
use crate::output::Informe;
use crate::plugins;

/// Estado de un binario respecto al lockfile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Estado {
    /// Está registrado y su hash sigue siendo el mismo.
    Registrado,
    /// El binario está pero nadie lo ha autorizado.
    SinRegistrar,
    /// Está registrado con **otro** hash: alguien lo ha cambiado.
    Alterado,
    /// El lockfile lo autoriza pero el binario no está en el directorio.
    Ausente,
}

impl Estado {
    const fn como_cadena(self) -> &'static str {
        match self {
            Self::Registrado => "registrado",
            Self::SinRegistrar => "sin registrar",
            Self::Alterado => "ALTERADO",
            Self::Ausente => "ausente",
        }
    }

    /// Si este estado impide ejecutar el binario.
    const fn es_fallo(self) -> bool {
        !matches!(self, Self::Registrado)
    }
}

/// `plugin list`: qué hay en el directorio y qué dice el lockfile de ello.
///
/// # Errors
/// Devuelve [`CliError::Plugin`] si el directorio o el lockfile no se pueden
/// leer. Que un plugin esté sin registrar **no** es un error aquí: es
/// justamente lo que este comando existe para enseñar.
pub fn listar(ctx: &Contexto) -> Result<Informe, CliError> {
    let (estados, _) = inventario(ctx)?;

    let humano = if estados.is_empty() {
        format!("no hay ningún plugin en «{}»", ctx.dir_plugins.display())
    } else {
        estados
            .iter()
            .map(|(nombre, estado)| format!("{nombre}: {}", estado.como_cadena()))
            .collect::<Vec<_>>()
            .join("\n")
    };

    Ok(Informe::new(
        humano,
        serde_json::json!({
            "comando": "plugin list",
            "dir": ctx.dir_plugins.to_string_lossy(),
            "lockfile": ctx.ruta_lockfile.to_string_lossy(),
            "plugins": estados.iter().map(|(nombre, estado)| serde_json::json!({
                "nombre": nombre,
                "estado": estado.como_cadena(),
                "usable": !estado.es_fallo(),
            })).collect::<Vec<_>>(),
        }),
    ))
}

/// `plugin verify`: comprobar todos los hashes **sin arrancar nada**.
///
/// Es la comprobación que se puede hacer en una máquina en la que no se quiere
/// ejecutar ningún plugin: leer ficheros y comparar digests, nada más.
///
/// # Errors
/// Devuelve [`CliError::Plugin`] si el directorio o el lockfile no se pueden
/// leer. Los binarios que no cuadran salen **dentro** del informe con el fallo
/// puesto: el comando existe para enumerarlos, no para pararse en el primero.
pub fn verificar(ctx: &Contexto) -> Result<Informe, CliError> {
    let (estados, _) = inventario(ctx)?;

    let fallos: Vec<&(String, Estado)> = estados.iter().filter(|(_, e)| e.es_fallo()).collect();
    let informe = Informe::new(
        estados
            .iter()
            .map(|(nombre, estado)| format!("{nombre}: {}", estado.como_cadena()))
            .collect::<Vec<_>>()
            .join("\n"),
        serde_json::json!({
            "comando": "plugin verify",
            "total": estados.len(),
            "fallidos": fallos.len(),
            "plugins": estados.iter().map(|(nombre, estado)| serde_json::json!({
                "nombre": nombre,
                "estado": estado.como_cadena(),
                "usable": !estado.es_fallo(),
            })).collect::<Vec<_>>(),
        }),
    );

    if fallos.is_empty() {
        return Ok(informe);
    }

    let detalle = fallos
        .iter()
        .map(|(nombre, estado)| format!("  {nombre}: {}", estado.como_cadena()))
        .collect::<Vec<_>>()
        .join("\n");
    Ok(informe.con_fallo(CliError::plugin(format!(
        "{} de {} plugins no se pueden ejecutar:\n{detalle}\nSi los cambios son esperados, \
         vuelve a registrarlos con `shieldbk plugin lock`. Si no lo son, NO los ejecutes: un \
         plugin recibe las credenciales de tu base de datos y de tu almacenamiento",
        fallos.len(),
        estados.len()
    ))))
}

/// `plugin lock`: registrar el hash de cada binario del directorio.
///
/// Registra **lo que hay ahora**, sin preguntar. Es lo correcto: quien ejecuta
/// este comando está diciendo «estos binarios son los que quiero», y la
/// confianza en su origen es una decisión suya. Lo que el lockfile garantiza a
/// partir de aquí es que sigan siendo esos.
///
/// # Errors
/// Devuelve [`CliError::Plugin`] si el directorio no se puede leer o el
/// lockfile no se puede escribir.
pub fn lock(ctx: &Contexto) -> Result<Informe, CliError> {
    let binarios = plugins::binarios(&ctx.dir_plugins)?;

    // Se parte del lockfile existente y no de uno vacío: un `lock` no puede
    // borrar en silencio la autorización de un plugin que hoy no está montado.
    let mut lockfile = Lockfile::load(&ctx.ruta_lockfile)?;
    let mut registrados = Vec::with_capacity(binarios.len());
    for (nombre, ruta) in &binarios {
        lockfile.register(nombre, ruta)?;
        registrados.push(nombre.clone());
    }

    crear_directorio_de(ctx)?;
    lockfile.save(&ctx.ruta_lockfile)?;

    let humano = if registrados.is_empty() {
        format!(
            "no había ningún plugin que registrar en «{}»",
            ctx.dir_plugins.display()
        )
    } else {
        format!(
            "{} plugins registrados en «{}»: {}",
            registrados.len(),
            ctx.ruta_lockfile.display(),
            registrados.join(", ")
        )
    };

    Ok(Informe::new(
        humano,
        serde_json::json!({
            "comando": "plugin lock",
            "lockfile": ctx.ruta_lockfile.to_string_lossy(),
            "registrados": registrados,
        }),
    ))
}

/// `plugin docs <plugin>`: el esquema de configuración, en una tabla.
///
/// # Errors
/// Devuelve [`CliError::Plugin`] si el binario no está, no está autorizado o no
/// arranca.
pub async fn docs(ctx: &Contexto, nombre: &str) -> Result<Informe, CliError> {
    let cliente = plugins::arrancar(ctx, nombre).await?;
    let esquema = cliente.schema().await;
    plugins::cerrar(cliente).await;
    let esquema = esquema?;

    Ok(Informe::new(
        tabla(nombre, &esquema),
        serde_json::json!({
            "comando": "plugin docs",
            "plugin": nombre,
            "campos": esquema.iter().map(|campo| serde_json::json!({
                "nombre": campo.name,
                "tipo": tipo_de(campo),
                "requerido": campo.required,
                "secreto": campo.secret,
                "descripcion": campo.description,
                "por_defecto": campo.default_value,
            })).collect::<Vec<_>>(),
        }),
    ))
}

/// Cruza lo que hay en el directorio con lo que dice el lockfile.
///
/// Se mira en las dos direcciones a propósito: un binario que está pero no
/// está registrado y un registro cuyo binario ha desaparecido son problemas
/// distintos, y solo mirando el directorio se vería el primero.
fn inventario(ctx: &Contexto) -> Result<(Vec<(String, Estado)>, Lockfile), CliError> {
    let binarios = plugins::binarios(&ctx.dir_plugins)?;
    let lockfile = Lockfile::load(&ctx.ruta_lockfile)?;

    let mut estados: Vec<(String, Estado)> = binarios
        .iter()
        .map(|(nombre, ruta)| {
            let estado = match lockfile.verify(nombre, ruta) {
                Ok(()) => Estado::Registrado,
                Err(LockfileError::NotRegistered { .. }) => Estado::SinRegistrar,
                Err(_) => Estado::Alterado,
            };
            (nombre.clone(), estado)
        })
        .collect();

    for registrado in lockfile.names() {
        if !binarios.iter().any(|(nombre, _)| nombre == &registrado) {
            estados.push((registrado, Estado::Ausente));
        }
    }

    estados.sort_by(|a, b| a.0.cmp(&b.0));
    Ok((estados, lockfile))
}

/// Crea el directorio del lockfile si hace falta.
///
/// Es la primera escritura de una instalación nueva: sin esto, `plugin lock`
/// fallaría con un «no such file or directory» que habla del directorio padre
/// y no del lockfile, que es lo que el usuario cree estar creando.
fn crear_directorio_de(ctx: &Contexto) -> Result<(), CliError> {
    let Some(padre) = ctx.ruta_lockfile.parent() else {
        return Ok(());
    };
    if padre.as_os_str().is_empty() || padre.is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(padre).map_err(|fuente| {
        CliError::plugin(format!(
            "no se pudo crear el directorio del lockfile «{}»: {fuente}",
            padre.display()
        ))
    })
}

/// El nombre legible del tipo de un campo.
fn tipo_de(campo: &Field) -> &'static str {
    match FieldType::try_from(campo.r#type) {
        Ok(FieldType::String) => "string",
        Ok(FieldType::Int) => "int",
        Ok(FieldType::Bool) => "bool",
        Ok(FieldType::Duration) => "duration",
        Ok(FieldType::Path) => "path",
        Ok(FieldType::List) => "list",
        Ok(FieldType::Unspecified) | Err(_) => "desconocido",
    }
}

/// La tabla que se lee. Columnas alineadas al ancho de su contenido: una
/// tabla con anchos fijos se rompe con el primer plugin que tenga un campo de
/// nombre largo.
fn tabla(plugin: &str, campos: &[Field]) -> String {
    if campos.is_empty() {
        return format!("el plugin «{plugin}» no acepta ningún campo de configuración");
    }

    let cabeceras = ["CAMPO", "TIPO", "REQ", "SECRETO", "POR DEFECTO"];
    let filas: Vec<[String; 5]> = campos
        .iter()
        .map(|c| {
            [
                c.name.clone(),
                tipo_de(c).to_owned(),
                si_no(c.required),
                si_no(c.secret),
                // El valor por defecto es parte del esquema que el plugin
                // publica, no un valor configurado: no hay nada que ocultar.
                if c.default_value.is_empty() {
                    "—".to_owned()
                } else {
                    c.default_value.clone()
                },
            ]
        })
        .collect();

    let mut anchos = cabeceras.map(str::len);
    for fila in &filas {
        for (ancho, celda) in anchos.iter_mut().zip(fila) {
            *ancho = (*ancho).max(celda.chars().count());
        }
    }

    let mut texto = format!("campos de configuración de «{plugin}»\n\n");
    for (i, cabecera) in cabeceras.iter().enumerate() {
        let _ = write!(texto, "{cabecera:<ancho$}  ", ancho = anchos[i]);
    }
    texto.push('\n');

    for (fila, campo) in filas.iter().zip(campos) {
        for (i, celda) in fila.iter().enumerate() {
            let relleno = anchos[i].saturating_sub(celda.chars().count());
            let _ = write!(texto, "{celda}{:relleno$}  ", "");
        }
        texto.push('\n');
        if !campo.description.is_empty() {
            let _ = writeln!(texto, "    {}", campo.description);
        }
    }

    texto.trim_end().to_owned()
}

fn si_no(valor: bool) -> String {
    if valor { "sí" } else { "no" }.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn campo(nombre: &str, tipo: FieldType, requerido: bool, secreto: bool) -> Field {
        Field {
            name: nombre.into(),
            r#type: tipo as i32,
            required: requerido,
            secret: secreto,
            description: format!("descripción de {nombre}"),
            default_value: String::new(),
        }
    }

    #[test]
    fn solo_el_estado_registrado_permite_ejecutar() {
        assert!(!Estado::Registrado.es_fallo());
        for malo in [Estado::SinRegistrar, Estado::Alterado, Estado::Ausente] {
            assert!(
                malo.es_fallo(),
                "{malo:?} no puede dar por bueno un binario"
            );
        }
    }

    #[test]
    fn la_tabla_muestra_las_cinco_columnas_del_esquema() {
        let texto = tabla(
            "postgres",
            &[
                campo("host", FieldType::String, true, false),
                campo("password", FieldType::String, true, true),
            ],
        );
        for cabecera in ["CAMPO", "TIPO", "REQ", "SECRETO", "POR DEFECTO"] {
            assert!(texto.contains(cabecera), "falta «{cabecera}»:\n{texto}");
        }
        assert!(texto.contains("host"));
        assert!(texto.contains("password"));
        assert!(texto.contains("descripción de host"));
    }

    #[test]
    fn la_tabla_marca_los_campos_secretos_sin_ensenar_ningun_valor() {
        // `docs` describe el esquema. Un comando que además imprimiera «lo que
        // hay configurado» imprimiría la contraseña.
        let mut secreto = campo("password", FieldType::String, true, true);
        secreto.default_value = String::new();
        let texto = tabla("postgres", &[secreto]);
        assert!(texto.contains("sí"), "el campo secreto se marca:\n{texto}");
        assert!(
            !texto.to_lowercase().contains("hunter2"),
            "no puede haber valores aquí"
        );
    }

    #[test]
    fn un_plugin_sin_campos_lo_dice_en_vez_de_ensenar_una_tabla_vacia() {
        let texto = tabla("trivial", &[]);
        assert!(texto.contains("no acepta ningún campo"), "{texto}");
    }

    #[test]
    fn los_tipos_del_protocolo_tienen_nombre_legible() {
        assert_eq!(tipo_de(&campo("a", FieldType::Path, false, false)), "path");
        assert_eq!(tipo_de(&campo("a", FieldType::Int, false, false)), "int");
        assert_eq!(tipo_de(&campo("a", FieldType::List, false, false)), "list");
        // Un plugin más nuevo puede mandar un tipo que este núcleo no conoce:
        // se dice, no se rompe.
        let raro = Field {
            r#type: 99,
            ..campo("a", FieldType::Int, false, false)
        };
        assert_eq!(tipo_de(&raro), "desconocido");
    }
}
