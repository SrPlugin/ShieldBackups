//! Subir un artefacto a R2.
//!
//! Es la parte más delicada del plugin, y lo es por dos motivos que no se ven
//! hasta que duelen:
//!
//! 1. **Las partes tienen que medir todas lo mismo salvo la última.** S3 lo
//!    tolera; R2 no. De eso se encarga [`Troceador`], que está aparte y
//!    probado sin red.
//! 2. **Un multipart que falla hay que abortarlo.** Las partes ya subidas no
//!    aparecen en un `ListObjects` —el objeto no existe todavía— pero ocupan y
//!    **se facturan indefinidamente**. Por eso, en cuanto existe un
//!    `upload_id`, todo lo demás ocurre dentro de [`subir_partes`] y el único
//!    camino de vuelta pasa por el `match` de [`subir`], que aborta ante
//!    cualquier `Err`. Un `?` suelto por encima de ese `match` sería
//!    exactamente el fallo que esta estructura impide.
//!
//! ## Memoria
//!
//! Cada parte se acumula entera en memoria mientras se sube, así que el techo
//! de memoria de una subida es **`part_size` × `concurrency`**. Con los valores
//! por defecto —64 MiB y 4 partes a la vez— son 256 MiB. Subir ambos números
//! sin pensarlo contradice la promesa de memoria acotada del resto del
//! programa: multiplicar la concurrencia por cuatro también multiplica por
//! cuatro la memoria, no solo la velocidad.

use std::path::Path;

use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart, StorageClass};
use sb_plugin_sdk::tonic::Status;
use sb_plugin_sdk::{EmisorProgreso, connect_data};
use tokio::net::UnixStream;
use tokio::task::JoinSet;

use crate::cliente::{Contexto, ErrorDeR2, traducir};
use crate::config::PARTES_MAXIMAS;
use crate::trozos::Troceador;

/// Sube el artefacto que llega por `socket` a la clave `clave`, ya prefijada.
///
/// Elige entre `PutObject` y multipart según lo que quepa en una parte, y en el
/// segundo caso garantiza que ningún fallo deje la subida abierta.
///
/// # Errors
///
/// [`Status`] con el motivo ya depurado: el error del SDK de AWS no se propaga
/// nunca, porque arrastra la petición que lo provocó y con ella la cabecera de
/// autorización.
pub async fn subir(
    contexto: &Contexto,
    clave: &str,
    socket: &str,
    progreso: &mut EmisorProgreso,
) -> Result<(), Status> {
    let canal = conectar(socket).await?;
    let tamano_de_parte = contexto.config.part_size;
    let mut troceador = Troceador::new(canal, tamano_de_parte);

    // La primera parte decide el camino. Leerla es obligatorio de todas formas,
    // así que no cuesta nada.
    let primera = troceador
        .siguiente()
        .await
        .map_err(|e| fallo_de_canal(&e))?
        .unwrap_or_default();

    // Objeto pequeño: una llamada en vez de tres, y ningún multipart que se
    // pueda quedar huérfano. Los manifiestos, que son diminutos y se escriben
    // en cada backup, pasan siempre por aquí.
    if primera.len() < tamano_de_parte {
        return directo(contexto, clave, primera, progreso).await;
    }

    let upload_id = crear(contexto, clave).await?;

    // A partir de esta línea existe una subida abierta en R2 que **no puede
    // quedarse abierta**. Todo lo que falta vive dentro de `subir_partes`, cuyo
    // único camino de salida es este `match`: no hay forma de saltarse el
    // aborto sin borrar el `match` entero.
    //
    // Las tareas de las partes se crean aquí, y no dentro, para poder pararlas
    // antes de abortar.
    let mut tareas = JoinSet::new();
    match subir_partes(
        contexto,
        clave,
        &upload_id,
        primera,
        troceador,
        &mut tareas,
        progreso,
    )
    .await
    {
        Ok(()) => Ok(()),
        Err(e) => {
            // Primero se cancelan las partes que seguían en vuelo y se espera a
            // que terminen; solo después se aborta. Al revés, una parte que
            // llegara a R2 después del aborto se quedaría huérfana igualmente,
            // que es justo lo que el aborto viene a evitar.
            tareas.shutdown().await;
            abortar(contexto, clave, &upload_id).await;
            Err(e)
        }
    }
}

/// El objeto entero de una vez.
async fn directo(
    contexto: &Contexto,
    clave: &str,
    cuerpo: Vec<u8>,
    progreso: &mut EmisorProgreso,
) -> Result<(), Status> {
    let bytes = cuerpo.len();
    contexto
        .cliente
        .put_object()
        .bucket(&contexto.config.bucket)
        .key(clave)
        .storage_class(clase(contexto))
        .body(ByteStream::from(cuerpo))
        .send()
        .await
        .map_err(|e| traducir("PutObject", &e))?;
    progreso.avanzar(bytes).await;
    tracing::debug!(clave = %clave, bytes, "artefacto subido en una sola llamada");
    Ok(())
}

/// Abre la subida multipart y devuelve su identificador.
async fn crear(contexto: &Contexto, clave: &str) -> Result<String, Status> {
    let salida = contexto
        .cliente
        .create_multipart_upload()
        .bucket(&contexto.config.bucket)
        .key(clave)
        .storage_class(clase(contexto))
        .send()
        .await
        .map_err(|e| traducir("CreateMultipartUpload", &e))?;
    // Sin `upload_id` no hay nada que abortar desde aquí: o la subida no llegó
    // a existir, o existe y R2 no nos dijo su identificador, y en ese segundo
    // caso el único remedio posible es `shieldbk storage gc`, que lista las
    // incompletas del bucket. Por eso este error puede salir por `?` sin más.
    salida.upload_id().map(ToString::to_string).ok_or_else(|| {
        Status::internal("R2 aceptó `CreateMultipartUpload` pero no devolvió un `upload_id`")
    })
}

/// Sube todas las partes y cierra el multipart.
///
/// **Toda la función puede fallar libremente**: quien la llama aborta la subida
/// ante cualquier `Err`, incluido el de `CompleteMultipartUpload`.
///
/// Mantiene hasta `concurrency` partes subiéndose a la vez. El hueco se espera
/// **antes** de leer la siguiente parte, no después: así nunca hay más de
/// `concurrency` partes vivas en memoria a la vez.
///
/// `tareas` viene de fuera para que quien llama pueda pararlas antes de
/// abortar, incluso —y sobre todo— cuando esta función sale por un error.
async fn subir_partes(
    contexto: &Contexto,
    clave: &str,
    upload_id: &str,
    primera: Vec<u8>,
    mut troceador: Troceador<UnixStream>,
    tareas: &mut JoinSet<Result<ParteSubida, ErrorDeR2>>,
    progreso: &mut EmisorProgreso,
) -> Result<(), Status> {
    let concurrencia = contexto.config.concurrency.max(1);
    let mut completadas: Vec<CompletedPart> = Vec::new();
    let mut pendiente = Some(primera);
    let mut indice: u64 = 0;

    loop {
        // Primero el hueco, después la lectura: al revés habría `concurrency`
        // partes en vuelo más la que se está leyendo.
        while tareas.len() >= concurrencia {
            recoger(tareas, &mut completadas, progreso).await?;
        }

        let parte = match pendiente.take() {
            Some(p) => p,
            None => match troceador
                .siguiente()
                .await
                .map_err(|e| fallo_de_canal(&e))?
            {
                Some(p) => p,
                None => break,
            },
        };

        indice += 1;
        if indice > PARTES_MAXIMAS {
            // La configuración valida esto contra `max_object_gb`, pero el
            // artefacto real puede ser mayor de lo que nadie esperaba. Mejor
            // pararlo aquí que dejar que R2 rechace la parte 10 001.
            return Err(Status::out_of_range(format!(
                "el artefacto no cabe en las {PARTES_MAXIMAS} partes que admite una subida multipart con partes de {} bytes: sube `part_size_mb`",
                contexto.config.part_size
            )));
        }
        // Tras la comprobación de arriba el índice nunca pasa de 10 000.
        let numero = i32::try_from(indice).unwrap_or(i32::MAX);

        tareas.spawn(subir_una(
            contexto.cliente.clone(),
            contexto.config.bucket.clone(),
            clave.to_string(),
            upload_id.to_string(),
            numero,
            parte,
        ));
    }

    while !tareas.is_empty() {
        recoger(tareas, &mut completadas, progreso).await?;
    }

    // Las partes terminan en el orden en que R2 las conteste, que no es el
    // orden en que se mandaron. `CompleteMultipartUpload` exige la lista
    // ordenada por número de parte.
    completadas.sort_by_key(CompletedPart::part_number);

    contexto
        .cliente
        .complete_multipart_upload()
        .bucket(&contexto.config.bucket)
        .key(clave)
        .upload_id(upload_id)
        .multipart_upload(
            CompletedMultipartUpload::builder()
                .set_parts(Some(completadas))
                .build(),
        )
        .send()
        .await
        .map_err(|e| traducir("CompleteMultipartUpload", &e))?;

    tracing::debug!(
        clave = %clave,
        partes = indice,
        bytes = troceador.total(),
        "artefacto subido por multipart"
    );
    Ok(())
}

/// Lo que una parte deja al terminar.
struct ParteSubida {
    numero: i32,
    /// El `ETag` que R2 devolvió. `CompleteMultipartUpload` lo exige de vuelta.
    etiqueta: Option<String>,
    bytes: usize,
}

/// Sube una parte. Se ejecuta en su propia tarea, de ahí que reciba todo en
/// propiedad; el `Client` se clona barato porque comparte el pool de
/// conexiones.
async fn subir_una(
    cliente: aws_sdk_s3::Client,
    bucket: String,
    clave: String,
    upload_id: String,
    numero: i32,
    parte: Vec<u8>,
) -> Result<ParteSubida, ErrorDeR2> {
    let bytes = parte.len();
    let salida = cliente
        .upload_part()
        .bucket(bucket)
        .key(clave)
        .upload_id(upload_id)
        .part_number(numero)
        .body(ByteStream::from(parte))
        .send()
        .await
        .map_err(|e| traducir("UploadPart", &e))?;
    Ok(ParteSubida {
        numero,
        etiqueta: salida.e_tag().map(ToString::to_string),
        bytes,
    })
}

/// Espera a que termine una parte cualquiera y la anota.
///
/// El progreso se emite aquí y no al leer: lo que le interesa al operador es lo
/// que ya está en R2, no lo que se leyó del socket.
async fn recoger(
    tareas: &mut JoinSet<Result<ParteSubida, ErrorDeR2>>,
    completadas: &mut Vec<CompletedPart>,
    progreso: &mut EmisorProgreso,
) -> Result<(), Status> {
    let Some(union) = tareas.join_next().await else {
        return Ok(());
    };
    // El motivo del `JoinError` se resume en vez de imprimirse: su `Display`
    // incluye el mensaje del pánico, que es texto ajeno a este módulo.
    let resultado = union.map_err(|e| {
        Status::internal(if e.is_panic() {
            "la subida de una parte entró en pánico"
        } else {
            "la subida de una parte fue cancelada"
        })
    })?;
    let parte = resultado?;
    progreso.avanzar(parte.bytes).await;
    completadas.push(
        CompletedPart::builder()
            .part_number(parte.numero)
            .set_e_tag(parte.etiqueta)
            .build(),
    );
    Ok(())
}

/// Aborta la subida multipart. No devuelve error a propósito: se la llama
/// **desde un camino que ya falló**, y el fallo que se le va a contar al núcleo
/// es el original, no este.
///
/// Si el aborto tampoco sale, lo único que queda es dejarlo dicho en el log:
/// las partes ya subidas siguen ahí, invisibles en un `ListObjects`, y se
/// facturan hasta que alguien las quite.
async fn abortar(contexto: &Contexto, clave: &str, upload_id: &str) {
    match contexto
        .cliente
        .abort_multipart_upload()
        .bucket(&contexto.config.bucket)
        .key(clave)
        .upload_id(upload_id)
        .send()
        .await
    {
        Ok(_) => {
            tracing::warn!(clave = %clave, "subida multipart abortada tras un fallo");
        }
        Err(e) => {
            let motivo = traducir("AbortMultipartUpload", &e);
            tracing::error!(
                clave = %clave,
                error = %motivo,
                "no se pudo abortar la subida multipart: las partes ya subidas quedan huérfanas, \
                 no aparecen al listar el bucket y se facturan indefinidamente. \
                 Ejecuta `shieldbk storage gc <destino>` para eliminarlas"
            );
        }
    }
}

/// La clase de almacenamiento configurada, en el tipo que espera el SDK.
fn clase(contexto: &Contexto) -> StorageClass {
    StorageClass::from(contexto.config.storage_class.como_str())
}

/// Se conecta al canal de datos que creó el núcleo.
async fn conectar(socket: &str) -> Result<UnixStream, Status> {
    connect_data(Path::new(socket)).await.map_err(|e| {
        Status::unavailable(format!(
            "no se pudo abrir el canal de datos `{socket}`: {e}"
        ))
    })
}

/// Un fallo leyendo el canal de datos es del otro extremo, no de R2.
fn fallo_de_canal(e: &std::io::Error) -> Status {
    Status::unavailable(format!("fallo leyendo el canal de datos: {e}"))
}
