//! Plantillas para la clave con la que se guarda un artefacto en el destino.
//!
//! Una clave se escribe con marcadores entre llaves, por ejemplo
//! `{target}/{yyyy}/{mm}/{dd}/{target}-{timestamp}-{engine}.dump.zst.age`, y
//! [`render`] los sustituye por los valores de un [`NamingContext`].
//!
//! El destino puede ser un sistema de archivos (el plugin de disco local),
//! así que la clave resultante se valida antes de devolverla: una plantilla
//! —o un nombre de target, que también viene de la configuración del
//! usuario— no puede acabar escribiendo fuera del directorio de backups.

use time::OffsetDateTime;

/// Marcadores que [`render`] sabe sustituir. Se usa también para construir el
/// mensaje de error cuando la plantilla nombra uno que no existe: quien se
/// equivoca escribiendo una plantilla necesita ver la lista, no solo un «no».
const MARCADORES: [&str; 7] = [
    "target",
    "engine",
    "storage",
    "timestamp",
    "yyyy",
    "mm",
    "dd",
];

/// Longitud máxima de una clave, en **bytes**.
///
/// Es el límite de S3 y de Cloudflare R2, el más restrictivo de los destinos
/// previstos: el disco local y SFTP admiten rutas más largas, pero una clave
/// que solo vale para algunos destinos no es una clave portable. Se mide en
/// bytes y no en caracteres porque así lo mide el destino: un nombre de 600
/// letras acentuadas ocupa 1200 bytes.
///
/// Rechazarla aquí evita que el backup falle —o que la clave se trunque en
/// silencio— a mitad de la subida.
pub const MAX_CLAVE_BYTES: usize = 1024;

#[derive(Debug, thiserror::Error)]
pub enum NamingError {
    #[error(
        "la plantilla usa el marcador «{marcador}», que no existe. Los marcadores válidos son: \
         {validos}"
    )]
    MarcadorDesconocido { marcador: String, validos: String },
    #[error("la clave «{clave}» no se puede usar: {motivo}")]
    RutaInsegura { clave: String, motivo: String },
}

/// Valores con los que se rellena una plantilla.
///
/// Los tres campos de fecha (`year`, `month`, `day`) son redundantes con
/// `timestamp` a propósito: permiten particionar el destino en carpetas sin
/// que la plantilla tenga que trocear la marca de tiempo.
#[derive(Debug, Clone)]
pub struct NamingContext {
    pub target: String,
    pub engine: String,
    pub storage: String,
    pub timestamp: String,
    pub year: String,
    pub month: String,
    pub day: String,
}

impl NamingContext {
    /// Construye el contexto para un backup lanzado en `epoch_secs`.
    ///
    /// `epoch_secs` es UTC. La hora local no se usa nunca: un backup nocturno
    /// no puede cambiar de nombre porque el servidor cambie de huso o entre en
    /// horario de verano, y dos réplicas en husos distintos tienen que
    /// producir la misma clave para la misma marca.
    ///
    /// La marca se formatea como `YYYYMMDDTHHMMSSZ`. Si `epoch_secs` cae fuera
    /// del rango de fechas representables —solo con un reloj roto de decenas
    /// de miles de años— se cae al epoch: es preferible una clave visiblemente
    /// absurda a un pánico en mitad de un backup.
    #[must_use]
    pub fn new(target: &str, engine: &str, storage: &str, epoch_secs: i64) -> Self {
        let fecha =
            OffsetDateTime::from_unix_timestamp(epoch_secs).unwrap_or(OffsetDateTime::UNIX_EPOCH);
        let year = format!("{:04}", fecha.year());
        let month = format!("{:02}", u8::from(fecha.month()));
        let day = format!("{:02}", fecha.day());
        let timestamp = format!(
            "{year}{month}{day}T{:02}{:02}{:02}Z",
            fecha.hour(),
            fecha.minute(),
            fecha.second()
        );
        Self {
            target: target.to_owned(),
            engine: engine.to_owned(),
            storage: storage.to_owned(),
            timestamp,
            year,
            month,
            day,
        }
    }

    /// Valor de un marcador, o `None` si el nombre no es de los válidos.
    fn valor(&self, marcador: &str) -> Option<&str> {
        Some(match marcador {
            "target" => &self.target,
            "engine" => &self.engine,
            "storage" => &self.storage,
            "timestamp" => &self.timestamp,
            "yyyy" => &self.year,
            "mm" => &self.month,
            "dd" => &self.day,
            _ => return None,
        })
    }
}

/// Rellena `plantilla` con los valores de `ctx` y devuelve la clave del
/// artefacto.
///
/// Un `{` sin su `}` no es una plantilla sino una errata, y se trata como
/// texto literal: rechazar el backup entero por eso sería desproporcionado,
/// siempre que la clave resultante siga siendo segura.
///
/// La validación se hace sobre la clave **ya rellenada**, no sobre la
/// plantilla: el nombre del target sale de la configuración del usuario, así
/// que un target llamado `..` es tan peligroso como un `..` escrito a mano en
/// la plantilla.
///
/// # Limitación: resolución de segundo
///
/// `{timestamp}` tiene resolución de segundo. Dos backups del mismo target
/// lanzados dentro del mismo segundo producen **la misma clave**, y el segundo
/// sobrescribiría al primero en el destino. No se arregla aquí: la unicidad es
/// una propiedad de la plantilla, y quien la compone puede añadir un marcador
/// que la garantice. Lo que esta función promete es que la sustitución es
/// determinista, no que el resultado sea único.
///
/// # Errors
///
/// - [`NamingError::MarcadorDesconocido`] si la plantilla nombra un marcador
///   que no está en la lista de válidos.
/// - [`NamingError::RutaInsegura`] si la clave resultante está vacía, es
///   absoluta, contiene `\`, contiene algún carácter de control, ocupa más de
///   [`MAX_CLAVE_BYTES`], o alguno de sus segmentos separados por `/` está
///   vacío o es exactamente `.` o `..`.
pub fn render(plantilla: &str, ctx: &NamingContext) -> Result<String, NamingError> {
    let mut salida = String::with_capacity(plantilla.len());
    let mut resto = plantilla;

    while let Some(abre) = resto.find('{') {
        salida.push_str(&resto[..abre]);
        let tras_llave = &resto[abre + 1..];
        if let Some(cierra) = tras_llave.find('}') {
            let nombre = &tras_llave[..cierra];
            let valor = ctx
                .valor(nombre)
                .ok_or_else(|| NamingError::MarcadorDesconocido {
                    marcador: nombre.to_owned(),
                    validos: MARCADORES.join(", "),
                })?;
            salida.push_str(valor);
            resto = &tras_llave[cierra + 1..];
        } else {
            salida.push('{');
            resto = tras_llave;
        }
    }
    salida.push_str(resto);

    validar(&salida)?;
    Ok(salida)
}

/// Comprueba que una clave ya rellenada se puede entregar a un destino sin
/// que este escriba donde no debe.
fn validar(clave: &str) -> Result<(), NamingError> {
    let insegura = |motivo: &str| NamingError::RutaInsegura {
        clave: clave.to_owned(),
        motivo: motivo.to_owned(),
    };

    if clave.is_empty() {
        return Err(insegura("una clave vacía no identifica ningún artefacto"));
    }
    if clave.starts_with('/') {
        return Err(insegura(
            "empieza por «/», y una clave absoluta escribe fuera del directorio de backups \
             cuando el destino es un sistema de archivos",
        ));
    }
    if clave.contains('\\') {
        return Err(insegura(
            "contiene «\\», que en un destino Windows abre jerarquía igual que «/»",
        ));
    }
    if clave.contains('\0') {
        return Err(insegura(
            "contiene un byte nulo, que trunca la ruta en las APIs del sistema y dejaría el \
             artefacto en un sitio distinto del que dice la clave",
        ));
    }
    // El rango C0 (U+0000–U+001F), U+007F y el C1 (U+0080–U+009F). El byte
    // nulo ya se ha comprobado arriba porque su mensaje es más concreto; el
    // resto cae aquí.
    if let Some(control) = clave
        .chars()
        .find(|c| matches!(*c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}'))
    {
        return Err(insegura(&format!(
            "contiene el carácter de control U+{:04X}. La clave viaja en las cabeceras de la \
             petición al object storage, y un salto de línea ahí inyecta cabeceras en la \
             petición",
            control as u32
        )));
    }
    if clave.len() > MAX_CLAVE_BYTES {
        return Err(insegura(&format!(
            "ocupa {} bytes y el máximo son {MAX_CLAVE_BYTES}: es el límite de S3 y R2, el más \
             restrictivo de los destinos previstos. Aceptarla aquí solo trasladaría el fallo al \
             destino, a mitad del backup",
            clave.len()
        )));
    }
    // Solo el segmento completo es peligroso: «backup..2026.age» es un nombre
    // legítimo, «backup/../..» sube dos niveles. Lo mismo con «.»: los nombres
    // de artefacto llevan puntos, pero un segmento que es solo un punto no.
    for segmento in clave.split('/') {
        let motivo = match segmento {
            ".." => {
                "tiene un segmento «..», que sube un nivel y escribiría fuera del directorio de \
                 backups"
            }
            "." => {
                "tiene un segmento «.», que un sistema de archivos ignora y el object storage \
                 conserva: la misma clave apuntaría a dos objetos distintos según el destino"
            }
            "" => {
                "tiene un segmento vacío —dos «/» seguidos, o una «/» final—, que en un sistema \
                 de archivos colapsa y en el object storage no: dos claves distintas acabarían \
                 en el mismo objeto y se perdería la correspondencia entre clave y artefacto"
            }
            _ => continue,
        };
        return Err(insegura(motivo));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contexto() -> NamingContext {
        NamingContext {
            target: "produccion".into(),
            engine: "postgres".into(),
            storage: "r2".into(),
            timestamp: "20260821T100000Z".into(),
            year: "2026".into(),
            month: "08".into(),
            day: "21".into(),
        }
    }

    #[test]
    fn rellena_todos_los_marcadores() {
        let plantilla = "{target}/{yyyy}/{mm}/{dd}/{target}-{timestamp}-{engine}.dump.zst.age";
        assert_eq!(
            render(plantilla, &contexto()).unwrap(),
            "produccion/2026/08/21/produccion-20260821T100000Z-postgres.dump.zst.age"
        );
    }

    #[test]
    fn un_marcador_puede_repetirse() {
        assert_eq!(
            render("{target}/{target}", &contexto()).unwrap(),
            "produccion/produccion"
        );
    }

    #[test]
    fn el_marcador_de_destino_tambien_funciona() {
        assert_eq!(render("{storage}/x", &contexto()).unwrap(), "r2/x");
    }

    #[test]
    fn una_plantilla_sin_marcadores_se_devuelve_tal_cual() {
        assert_eq!(render("fijo.bin", &contexto()).unwrap(), "fijo.bin");
    }

    #[test]
    fn una_plantilla_vacia_se_rechaza() {
        // Una clave vacía no identifica nada.
        assert!(render("", &contexto()).is_err());
    }

    #[test]
    fn un_marcador_desconocido_se_rechaza() {
        let err = render("{target}/{inventado}", &contexto()).err().unwrap();
        let texto = err.to_string();
        assert!(texto.contains("inventado"));
        assert!(texto.contains("target"), "debe listar los válidos");
    }

    #[test]
    fn una_llave_sin_cerrar_es_texto_literal() {
        // Es un error de escritura, no una plantilla; mejor tratarlo como
        // texto que rechazarlo, siempre que el resultado sea una clave segura.
        assert_eq!(
            render("archivo{sin-cerrar", &contexto()).unwrap(),
            "archivo{sin-cerrar"
        );
    }

    #[test]
    fn se_rechaza_una_plantilla_que_escapa_del_prefijo() {
        // El destino puede ser un sistema de archivos: un `..` escribiría
        // fuera del directorio de backups.
        assert!(matches!(
            render("{target}/../../otro", &contexto()).err().unwrap(),
            NamingError::RutaInsegura { .. }
        ));
    }

    #[test]
    fn se_rechaza_un_punto_punto_al_principio() {
        assert!(render("../fuera", &contexto()).is_err());
    }

    #[test]
    fn se_rechaza_un_punto_punto_al_final() {
        assert!(render("{target}/..", &contexto()).is_err());
    }

    #[test]
    fn un_nombre_que_contiene_dos_puntos_sin_ser_segmento_se_acepta() {
        // «..» solo es peligroso como segmento completo; «backup..2026» no lo es.
        assert!(render("backup..2026.age", &contexto()).is_ok());
    }

    #[test]
    fn se_rechaza_una_plantilla_absoluta() {
        assert!(matches!(
            render("/absoluta/{target}", &contexto()).err().unwrap(),
            NamingError::RutaInsegura { .. }
        ));
    }

    #[test]
    fn se_rechaza_un_byte_nulo() {
        assert!(render("archivo\0oculto", &contexto()).is_err());
    }

    #[test]
    fn se_rechaza_una_barra_invertida() {
        // En un destino Windows abriría jerarquía igual que la barra normal.
        assert!(render("carpeta\\fuera", &contexto()).is_err());
    }

    #[test]
    fn el_contexto_se_construye_desde_una_marca_de_tiempo() {
        let c = NamingContext::new("t", "e", "s", 1_755_770_400);
        assert_eq!(c.year.len(), 4);
        assert_eq!(c.month.len(), 2);
        assert_eq!(c.day.len(), 2);
        assert!(c.timestamp.ends_with('Z'), "la marca es UTC");
        assert_eq!(c.timestamp.len(), 16, "formato YYYYMMDDTHHMMSSZ");
    }

    #[test]
    fn la_marca_de_tiempo_es_utc_y_no_depende_del_huso_local() {
        // Un backup nocturno no puede cambiar de nombre porque el servidor
        // cambie de huso o entre en horario de verano.
        let c = NamingContext::new("t", "e", "s", 0);
        assert_eq!(c.timestamp, "19700101T000000Z");
        assert_eq!(c.year, "1970");
        assert_eq!(c.month, "01");
        assert_eq!(c.day, "01");
    }

    #[test]
    fn la_fecha_del_contexto_coincide_con_la_marca() {
        let c = NamingContext::new("t", "e", "s", 1_755_770_400);
        assert!(
            c.timestamp
                .starts_with(&format!("{}{}{}", c.year, c.month, c.day))
        );
    }

    #[test]
    fn dos_backups_en_el_mismo_segundo_producen_la_misma_clave() {
        // Documenta una limitación real: la plantilla por defecto tiene
        // resolución de segundo. Quien lance dos backups del mismo target en
        // el mismo segundo sobrescribiría uno con otro.
        let a = NamingContext::new("t", "e", "s", 1_755_770_400);
        let b = NamingContext::new("t", "e", "s", 1_755_770_400);
        assert_eq!(a.timestamp, b.timestamp);
    }

    #[test]
    fn se_rechaza_un_retorno_de_carro() {
        // La clave viaja en cabeceras HTTP hacia el object storage: un \r\n
        // es inyección de cabeceras en la petición.
        assert!(render("archivo\rmalo", &contexto()).is_err());
    }

    #[test]
    fn se_rechaza_un_salto_de_linea() {
        assert!(render("archivo\nmalo", &contexto()).is_err());
    }

    #[test]
    fn se_rechaza_cualquier_caracter_de_control() {
        for c in ['\u{1}', '\u{7}', '\u{1b}', '\u{7f}', '\u{9b}'] {
            let plantilla = format!("archivo{c}malo");
            assert!(
                render(&plantilla, &contexto()).is_err(),
                "debería rechazar U+{:04X}",
                c as u32
            );
        }
    }

    #[test]
    fn un_nombre_de_target_con_salto_de_linea_tambien_se_rechaza() {
        // El vector real: el nombre viene de la configuración del usuario, no
        // de la plantilla.
        let mut ctx = contexto();
        ctx.target = "produccion\r\nX-Inyectada: si".into();
        assert!(render("{target}/x.age", &ctx).is_err());
    }

    #[test]
    fn se_rechaza_una_clave_mas_larga_que_el_limite_de_s3() {
        // S3 y R2 limitan las claves a 1024 bytes. Aceptarla aquí solo
        // traslada el fallo al destino, a mitad de un backup.
        let mut ctx = contexto();
        ctx.target = "a".repeat(2000);
        let err = render("{target}/x.age", &ctx).err().unwrap();
        assert!(matches!(err, NamingError::RutaInsegura { .. }));
        assert!(
            err.to_string().contains("1024"),
            "debe decir cuál es el límite"
        );
    }

    #[test]
    fn una_clave_justo_en_el_limite_se_acepta() {
        let mut ctx = contexto();
        ctx.target = "a".repeat(1024);
        assert!(render("{target}", &ctx).is_ok());
    }

    #[test]
    fn el_limite_se_mide_en_bytes_no_en_caracteres() {
        // Los nombres con acentos o emoji ocupan más de un byte, y el límite
        // del destino es de bytes.
        let mut ctx = contexto();
        ctx.target = "ñ".repeat(600); // 1200 bytes en UTF-8
        assert!(render("{target}", &ctx).is_err());
    }

    #[test]
    fn se_rechaza_un_segmento_vacio() {
        // `a//b` y `a/b` son la misma ruta en un sistema de archivos y dos
        // claves distintas en S3. Esa ambigüedad rompe la correspondencia
        // entre clave y artefacto de la que depende la retención.
        assert!(render("{target}//x.age", &contexto()).is_err());
    }

    #[test]
    fn se_rechaza_una_clave_que_termina_en_barra() {
        // Sería un «directorio», no un objeto.
        assert!(render("{target}/", &contexto()).is_err());
    }

    #[test]
    fn se_rechaza_un_segmento_de_un_solo_punto() {
        assert!(render("{target}/./x.age", &contexto()).is_err());
    }

    #[test]
    fn un_punto_dentro_de_un_nombre_sigue_siendo_valido() {
        // Solo el segmento completo es problemático: los nombres de artefacto
        // llevan puntos por todas partes.
        assert!(render("{target}/x.dump.zst.age", &contexto()).is_ok());
    }

    #[test]
    fn un_nombre_oculto_sigue_siendo_valido() {
        assert!(render(".shieldbk/{target}.age", &contexto()).is_ok());
    }
}
