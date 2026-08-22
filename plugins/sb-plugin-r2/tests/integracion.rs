// La excepción de `clippy.toml` para `unwrap` cubre los cuerpos de `#[test]`,
// pero este fichero es todo código de prueba: levantar el contenedor, montar el
// contexto y los ayudantes de put/get también lo son, y ahí un `unwrap` es
// exactamente lo que se quiere —que el test explote donde falló, con su línea.
#![allow(clippy::unwrap_used)]

//! El plugin de R2, contra un servidor de objetos de verdad.
//!
//! Hasta aquí todo lo que cubría este plugin eran funciones puras. Nada había
//! hablado nunca con un servidor, y las cosas que más fácilmente se rompen en
//! un destino —la paginación del listado, el tamaño de las partes de un
//! multipart, la subida que se queda abierta tras un fallo— **no se ven sin
//! uno**: un listado truncado no da error, da una lista corta.
//!
//! ## Por qué `MinIO`
//!
//! `MinIO` habla el protocolo de S3 y corre en Docker, así que ejercita el
//! plugin entero sin credenciales de Cloudflare, sin coste y sin red. Con él se
//! prueba lo que es de S3, que es casi todo.
//!
//! **Lo que `MinIO` no valida** es la regla propia de R2: todas las partes de un
//! multipart salvo la última deben medir lo mismo. `MinIO` tolera partes
//! desiguales, así que un plugin que las produjera pasaría estos tests y
//! fallaría en producción. Por eso
//! [`las_partes_de_un_multipart_miden_todas_lo_mismo_salvo_la_ultima`] mira los
//! tamaños él mismo, en vez de confiar en que el servidor los rechace. La
//! comprobación contra R2 real queda para otra tarea.
//!
//! ## Docker
//!
//! Sin Docker no hay servidor y estos tests se saltan solos, avisando por
//! stderr. Un test que no se puede ejecutar no puede fallar la compilación de
//! todo el mundo, pero tampoco puede pasar en silencio.

use std::collections::HashMap;
use std::future::Future;
use std::io::{BufRead as _, BufReader, Write as _};
use std::path::Path;
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::task::{Context, Poll};

use sb_plugin_r2::cliente::{self, Contexto, Estado};
use sb_plugin_r2::config::R2Config;
use sb_plugin_r2::plugin::PluginR2;
use sb_plugin_r2::storage::DestinoR2;
use sb_plugin_r2::{admin, put};
use sb_plugin_sdk::sb_proto::plugin_client::PluginClient;
use sb_plugin_sdk::sb_proto::plugin_server::Plugin as _;
use sb_plugin_sdk::sb_proto::storage_client::StorageClient;
use sb_plugin_sdk::sb_proto::storage_server::Storage as _;
use sb_plugin_sdk::sb_proto::value::Kind;
use sb_plugin_sdk::sb_proto::{
    ConfigureRequest, DeleteRequest, GetRequest, ListRequest, PreflightRequest, PutRequest, Value,
};
use sb_plugin_sdk::tonic::transport::Channel;
use sb_plugin_sdk::tonic::{Code, Request, Status};
use sb_plugin_sdk::{ProgressEmitter, progress_stream};
use sb_transport::{Bootstrap, DataChannel, EphemeralPki, Ready, connect_control};
use tempfile::TempDir;
use testcontainers::ContainerAsync;
use testcontainers::runners::AsyncRunner as _;
use testcontainers_modules::minio::MinIO;
use tokio::io::{AsyncRead, AsyncWriteExt as _, ReadBuf};

/// Un mebibyte, que es la unidad en la que se mide una parte del multipart.
const MIB: usize = 1024 * 1024;

/// Tamaño de parte con el que se prueban los multiparts: el mínimo del
/// protocolo. Cuanto más pequeña la parte, más partes salen de un objeto que
/// quepa en un test sin tardar un minuto.
const PARTE_MB: i64 = 5;

/// Objeto de prueba multiparte: 17 MiB con partes de 5 MiB son **tres partes
/// completas y un resto de 2 MiB**. El resto es lo que importa: un objeto que
/// midiera un múltiplo exacto no distinguiría un troceador correcto de uno que
/// pierde o repite la última parte.
const MULTIPARTE: usize = 17 * MIB;

// ---------------------------------------------------------------------------
// Docker
// ---------------------------------------------------------------------------

/// Si hay un demonio de contenedores al que testcontainers pueda hablarle.
///
/// Se pregunta una sola vez: `docker info` tarda lo suyo y estos tests son
/// trece.
fn hay_docker() -> bool {
    static DISPONIBLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *DISPONIBLE.get_or_init(|| {
        Command::new("docker")
            .args(["info", "--format", "{{.ServerVersion}}"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    })
}

/// El nombre del test que está corriendo, para el mensaje del salto.
macro_rules! function_name {
    () => {{
        fn f() {}
        let nombre = std::any::type_name_of_val(&f);
        // `integracion::el_test::{{closure}}::f` -> `el_test`. Los
        // `{{closure}}` los mete `#[tokio::test]`, que envuelve el cuerpo del
        // test en un futuro; el nombre útil es el último segmento que no lo es.
        nombre
            .strip_suffix("::f")
            .unwrap_or(nombre)
            .rsplit("::")
            .find(|segmento| !segmento.starts_with("{{"))
            .unwrap_or(nombre)
    }};
}

/// Sale del test sin fallar si no hay Docker, dejando dicho por qué.
///
/// Un `#[ignore]` fijo escondería estos tests también donde sí se pueden
/// ejecutar; un fallo duro rompería la compilación de quien no tiene Docker. El
/// aviso por stderr es lo que evita que un salto pase por un verde.
macro_rules! saltar_sin_docker {
    () => {
        if !hay_docker() {
            eprintln!(
                "SALTADO {}::{}: no hay Docker disponible, así que no se puede levantar el MinIO \
                 contra el que se prueba el plugin de R2. Arranca Docker y vuelve a ejecutarlo.",
                module_path!(),
                function_name!()
            );
            return;
        }
    };
}

// ---------------------------------------------------------------------------
// El servidor y el contexto del plugin
// ---------------------------------------------------------------------------

/// Un `MinIO` arrancado, con su endpoint ya resuelto.
///
/// El contenedor se guarda dentro: al destruirse el `Servidor`, testcontainers
/// para y borra el contenedor. Cada test levanta el suyo para que ninguno vea
/// lo que otro dejó en el bucket.
struct Servidor {
    _contenedor: ContainerAsync<MinIO>,
    endpoint: String,
}

/// Credenciales por defecto de la imagen de `MinIO`. No son un secreto: el
/// servidor vive dentro de un contenedor efímero y solo escucha en localhost.
const USUARIO: &str = "minioadmin";
const CLAVE: &str = "minioadmin";

async fn levantar_minio() -> Servidor {
    let contenedor = MinIO::default().start().await.unwrap();
    let host = contenedor.get_host().await.unwrap();
    let puerto = contenedor.get_host_port_ipv4(9000).await.unwrap();
    Servidor {
        endpoint: format!("http://{host}:{puerto}"),
        _contenedor: contenedor,
    }
}

fn texto(valor: &str) -> Value {
    Value {
        kind: Some(Kind::StringValue(valor.to_string())),
    }
}

fn entero(valor: i64) -> Value {
    Value {
        kind: Some(Kind::IntValue(valor)),
    }
}

/// La configuración que el núcleo mandaría por `Configure`, apuntando a `MinIO`.
///
/// `max_object_gb` va a 1 GB **a propósito**: con partes de 5 MiB y el tope de
/// 10 000 partes solo se llega a unos 52 GB, así que el valor por defecto de
/// 640 GB haría que `Configure` rechazara esta configuración. Es la validación
/// madrugadora de `config.rs` haciendo su trabajo.
fn valores(endpoint: &str, bucket: &str, prefijo: &str, parte_mb: i64) -> HashMap<String, Value> {
    HashMap::from([
        // El `account_id` solo se usa para derivar el endpoint, y aquí el
        // endpoint viene explícito: este campo existe precisamente para poder
        // apuntar a un MinIO local.
        ("account_id".to_string(), texto("cuenta-de-pruebas")),
        ("bucket".to_string(), texto(bucket)),
        ("access_key_id".to_string(), texto(USUARIO)),
        ("secret_access_key".to_string(), texto(CLAVE)),
        ("endpoint".to_string(), texto(endpoint)),
        ("prefix".to_string(), texto(prefijo)),
        ("part_size_mb".to_string(), entero(parte_mb)),
        ("max_object_gb".to_string(), entero(1)),
        ("concurrency".to_string(), entero(4)),
    ])
}

/// Un contexto del plugin apuntando al servidor, con el bucket ya creado.
async fn contexto(servidor: &Servidor, bucket: &str, prefijo: &str, parte_mb: i64) -> Contexto {
    let contexto = contexto_sin_bucket(servidor, bucket, prefijo, parte_mb);
    contexto
        .cliente
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .unwrap();
    contexto
}

/// Igual, pero sin crear el bucket: lo necesita el preflight que debe fallar.
fn contexto_sin_bucket(
    servidor: &Servidor,
    bucket: &str,
    prefijo: &str,
    parte_mb: i64,
) -> Contexto {
    let config =
        R2Config::from_values(&valores(&servidor.endpoint, bucket, prefijo, parte_mb)).unwrap();
    let cliente = cliente::construir(&config);
    Contexto { config, cliente }
}

/// El destino, montado sobre un contexto ya configurado.
fn destino(contexto: &Contexto) -> DestinoR2 {
    let estado = Estado::new("r2");
    estado.store(contexto.clone());
    DestinoR2::new(estado)
}

/// El servicio `Plugin`, ya configurado.
fn servicio(contexto: &Contexto) -> PluginR2 {
    let estado = Estado::new("r2");
    estado.store(contexto.clone());
    PluginR2::new(estado)
}

/// Ejecuta un trabajo que necesita un [`ProgressEmitter`] y devuelve su
/// resultado.
///
/// Un `ProgressEmitter` solo lo crea `progress_stream`, porque un emisor sin
/// flujo al otro lado no emitiría a nadie. Esta función hace lo que hace el
/// núcleo: consumir el flujo hasta el final y quedarse con el error si lo hubo.
async fn con_progreso<F, Fut>(trabajo: F) -> Result<(), Status>
where
    F: FnOnce(ProgressEmitter) -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), Status>> + Send + 'static,
{
    let mut recibidor = progress_stream(trabajo).into_inner().into_inner();
    let mut resultado = Ok(());
    while let Some(mensaje) = recibidor.recv().await {
        if let Err(e) = mensaje {
            resultado = Err(e);
        }
    }
    resultado
}

// ---------------------------------------------------------------------------
// Put y Get por el destino, con su canal de datos
// ---------------------------------------------------------------------------

/// Consume el flujo de progreso de un RPC de datos hasta el final.
async fn agotar(flujo: sb_plugin_sdk::ProgressStream) -> Result<(), Status> {
    let mut recibidor = flujo.into_inner();
    while let Some(mensaje) = recibidor.recv().await {
        mensaje?;
    }
    Ok(())
}

/// Guarda `contenido` bajo `clave` pasando por el destino y su canal de datos.
async fn poner(
    destino: &DestinoR2,
    sockets: &Path,
    nombre: &str,
    clave: &str,
    contenido: Vec<u8>,
) -> Result<(), Status> {
    let canal = DataChannel::create(sockets, nombre).unwrap();
    let ruta = canal.path().display().to_string();
    let flujo = destino
        .put(Request::new(PutRequest {
            key: clave.to_string(),
            data_socket: ruta,
        }))
        .await?
        .into_inner();

    let escritura = tokio::spawn(async move {
        let mut s = canal.accept().await.unwrap();
        s.write_all(&contenido).await.unwrap();
        s.shutdown().await.unwrap();
    });
    let resultado = agotar(flujo).await;
    // Si la subida falló, el escritor se lleva un `BrokenPipe` y entra en
    // pánico: el error que hay que enseñar es el primero, no el de rebote.
    match resultado {
        Ok(()) => {
            escritura.await.unwrap();
            Ok(())
        }
        Err(e) => {
            escritura.abort();
            Err(e)
        }
    }
}

/// Recupera lo guardado bajo `clave`.
async fn obtener(
    destino: &DestinoR2,
    sockets: &Path,
    nombre: &str,
    clave: &str,
) -> Result<Vec<u8>, Status> {
    let canal = DataChannel::create(sockets, nombre).unwrap();
    let ruta = canal.path().display().to_string();
    let flujo = destino
        .get(Request::new(GetRequest {
            key: clave.to_string(),
            data_socket: ruta,
        }))
        .await?
        .into_inner();

    let lectura = tokio::spawn(async move {
        let mut s = canal.accept().await.unwrap();
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut s, &mut buf)
            .await
            .unwrap();
        buf
    });
    agotar(flujo).await?;
    Ok(lectura.await.unwrap())
}

/// Bytes deterministas y no repetitivos: así una parte que se pierda, se repita
/// o se descoloque cambia el contenido y no solo el tamaño.
fn datos(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| u8::try_from((i * 31 + i / 251) % 256).unwrap_or(0))
        .collect()
}

// ---------------------------------------------------------------------------
// Fuentes de datos artificiales, para lo que un socket no sabe hacer
// ---------------------------------------------------------------------------

/// Una fuente que entrega unos bytes y **después falla**.
///
/// Existe porque un socket Unix no sabe fallar: cerrarlo es un fin de flujo
/// limpio, no un error, y el fallo a mitad de subida es justo lo que hay que
/// provocar para ver si el multipart se aborta.
struct FuenteQueFalla {
    datos: Vec<u8>,
    leidos: usize,
}

impl AsyncRead for FuenteQueFalla {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.leidos >= self.datos.len() {
            return Poll::Ready(Err(std::io::Error::other(
                "la fuente de datos se rompió a mitad de la subida",
            )));
        }
        let cuantos = buf.remaining().min(self.datos.len() - self.leidos);
        let desde = self.leidos;
        buf.put_slice(&self.datos[desde..desde + cuantos]);
        self.leidos += cuantos;
        Poll::Ready(Ok(()))
    }
}

// ---------------------------------------------------------------------------
// Los tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn sube_y_descarga_un_objeto_pequeno() {
    saltar_sin_docker!();
    let servidor = levantar_minio().await;
    let ctx = contexto(&servidor, "pequeno", "shieldbk", PARTE_MB).await;
    let destino = destino(&ctx);
    let sockets = tempfile::tempdir().unwrap();

    let contenido = datos(4096);
    poner(
        &destino,
        sockets.path(),
        "put",
        "produccion/backup.age",
        contenido.clone(),
    )
    .await
    .unwrap();

    let recuperado = obtener(&destino, sockets.path(), "get", "produccion/backup.age")
        .await
        .unwrap();
    assert_eq!(recuperado, contenido);
}

#[tokio::test(flavor = "multi_thread")]
async fn sube_y_descarga_un_objeto_multiparte_de_verdad() {
    saltar_sin_docker!();
    let servidor = levantar_minio().await;
    let ctx = contexto(&servidor, "multiparte", "shieldbk", PARTE_MB).await;
    let destino = destino(&ctx);
    let sockets = tempfile::tempdir().unwrap();

    // 17 MiB con partes de 5 MiB: tres completas y un resto de 2 MiB.
    let contenido = datos(MULTIPARTE);
    poner(
        &destino,
        sockets.path(),
        "put",
        "grande.age",
        contenido.clone(),
    )
    .await
    .unwrap();

    let recuperado = obtener(&destino, sockets.path(), "get", "grande.age")
        .await
        .unwrap();
    // Byte a byte, no solo el tamaño: un troceador que descolocara las partes
    // devolvería exactamente los mismos bytes en total.
    assert_eq!(recuperado.len(), MULTIPARTE);
    assert_eq!(
        recuperado, contenido,
        "el objeto multiparte no volvió igual"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn las_partes_de_un_multipart_miden_todas_lo_mismo_salvo_la_ultima() {
    saltar_sin_docker!();
    let servidor = levantar_minio().await;
    let ctx = contexto(&servidor, "partes", "shieldbk", PARTE_MB).await;
    let destino = destino(&ctx);
    let sockets = tempfile::tempdir().unwrap();

    // Los 17 MiB se escriben en el canal **sin cerrarlo**: el plugin sube las
    // tres partes completas y se queda esperando el resto de la cuarta. Ahí es
    // donde se pueden mirar las partes, que es antes de completar el multipart
    // y por tanto antes de que dejen de existir por separado.
    let canal = DataChannel::create(sockets.path(), "put").unwrap();
    let ruta = canal.path().display().to_string();
    let clave = "uniforme.age";
    let flujo = destino
        .put(Request::new(PutRequest {
            key: clave.to_string(),
            data_socket: ruta,
        }))
        .await
        .unwrap()
        .into_inner();

    let contenido = datos(MULTIPARTE);
    let copia = contenido.clone();
    let escritura = tokio::spawn(async move {
        let mut s = canal.accept().await.unwrap();
        s.write_all(&copia).await.unwrap();
        // Sin `shutdown`: el canal se cierra al soltar el stream, y eso pasa
        // cuando esta tarea termina. Se devuelve para poder soltarlo a mano.
        s
    });

    let completa = PARTE_MB * i64::try_from(MIB).unwrap();
    let tamanos = esperar_partes(&ctx, &ctx.config.clave(clave), 3).await;
    assert_eq!(tamanos.len(), 3);
    for (i, tamano) in tamanos.iter().enumerate() {
        assert_eq!(
            *tamano,
            completa,
            "la parte {} mide {tamano} y no {completa}: R2 exige que todas las partes salvo la \
             última midan lo mismo, y MinIO lo tolera sin protestar",
            i + 1
        );
    }

    // Se suelta el canal: el plugin ve el fin de flujo, sube la última parte y
    // completa el multipart.
    drop(escritura.await.unwrap());
    agotar(flujo).await.unwrap();

    let recuperado = obtener(&destino, sockets.path(), "get", clave)
        .await
        .unwrap();
    assert_eq!(recuperado, contenido);
}

/// Espera a que la subida multipart de `clave` tenga al menos `cuantas` partes
/// y devuelve sus tamaños, ordenados por número de parte.
///
/// Sondea porque las partes viajan por red: no hay un instante en el que estén
/// garantizadas, solo uno a partir del cual lo están.
async fn esperar_partes(contexto: &Contexto, clave: &str, cuantas: usize) -> Vec<i64> {
    let limite = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        if let Some(id) = subida_abierta(contexto, clave).await {
            let partes = contexto
                .cliente
                .list_parts()
                .bucket(&contexto.config.bucket)
                .key(clave)
                .upload_id(&id)
                .send()
                .await
                .unwrap();
            let mut encontradas: Vec<(i32, i64)> = partes
                .parts()
                .iter()
                .map(|p| (p.part_number().unwrap_or(0), p.size().unwrap_or(0)))
                .collect();
            if encontradas.len() >= cuantas {
                encontradas.sort_by_key(|(numero, _)| *numero);
                return encontradas.into_iter().map(|(_, tamano)| tamano).collect();
            }
        }
        assert!(
            std::time::Instant::now() < limite,
            "las {cuantas} primeras partes de `{clave}` no aparecieron en 60 s"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// El `upload_id` de la subida abierta de `clave`, si la hay.
async fn subida_abierta(contexto: &Contexto, clave: &str) -> Option<String> {
    contexto
        .cliente
        .list_multipart_uploads()
        .bucket(&contexto.config.bucket)
        .send()
        .await
        .unwrap()
        .uploads()
        .iter()
        .find(|s| s.key() == Some(clave))
        .and_then(|s| s.upload_id().map(ToString::to_string))
}

#[tokio::test(flavor = "multi_thread")]
async fn un_objeto_de_cero_bytes_se_sube_y_se_descarga() {
    saltar_sin_docker!();
    let servidor = levantar_minio().await;
    let ctx = contexto(&servidor, "vacio", "shieldbk", PARTE_MB).await;
    let destino = destino(&ctx);
    let sockets = tempfile::tempdir().unwrap();

    // Un artefacto vacío es legítimo —un volcado de una base sin datos— y es el
    // caso en el que un troceador ingenuo no emite ninguna parte y el objeto no
    // llega a existir.
    poner(&destino, sockets.path(), "put", "vacio.age", Vec::new())
        .await
        .unwrap();

    let recuperado = obtener(&destino, sockets.path(), "get", "vacio.age")
        .await
        .unwrap();
    assert!(recuperado.is_empty());

    // Y existe de verdad, con tamaño cero: no es que el listado lo esconda.
    let listado = admin::listar(&ctx, &ctx.config.clave("")).await.unwrap();
    assert_eq!(listado.len(), 1);
    assert_eq!(listado[0].clave, "vacio.age");
    assert_eq!(listado[0].tamano, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn descargar_una_clave_inexistente_da_not_found() {
    saltar_sin_docker!();
    let servidor = levantar_minio().await;
    let ctx = contexto(&servidor, "ausente", "shieldbk", PARTE_MB).await;
    let destino = destino(&ctx);
    let sockets = tempfile::tempdir().unwrap();

    // `not_found` y no un error genérico: quien restaura tiene que poder
    // distinguir «ese artefacto no existe» de «la transferencia se cortó».
    let e = obtener(&destino, sockets.path(), "get", "jamas-existio.age")
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::NotFound, "{}", e.message());
    assert!(
        e.message().contains("jamas-existio.age"),
        "el error no dice qué clave faltaba: {}",
        e.message()
    );
}

/// Mil cincuenta: `ListObjectsV2` devuelve como mucho 1000 por página, así que
/// un destino que se quedara con la primera devolvería 1000 y **nadie se
/// enteraría**. No daría error: daría una lista corta, con la que `verify --all`
/// diría que todo está bien tras mirar solo los mil primeros.
const OBJETOS_QUE_NO_CABEN_EN_UNA_PAGINA: usize = 1050;

#[tokio::test(flavor = "multi_thread")]
async fn el_listado_pagina_mas_alla_de_mil_objetos() {
    saltar_sin_docker!();
    let servidor = levantar_minio().await;
    let ctx = contexto(&servidor, "paginado", "shieldbk", PARTE_MB).await;

    let mut tareas = tokio::task::JoinSet::new();
    for i in 0..OBJETOS_QUE_NO_CABEN_EN_UNA_PAGINA {
        let cliente = ctx.cliente.clone();
        let bucket = ctx.config.bucket.clone();
        let clave = ctx.config.clave(&format!("lote/{i:05}.age"));
        tareas.spawn(async move {
            cliente
                .put_object()
                .bucket(bucket)
                .key(clave)
                .body(aws_sdk_s3::primitives::ByteStream::from_static(b"x"))
                .send()
                .await
                .unwrap();
        });
        // En paralelo, pero acotado: mil peticiones a la vez agotarían el pool
        // de conexiones antes que el servidor.
        while tareas.len() >= 32 {
            tareas.join_next().await.unwrap().unwrap();
        }
    }
    while let Some(t) = tareas.join_next().await {
        t.unwrap();
    }

    let encontrados = admin::listar(&ctx, &ctx.config.clave("")).await.unwrap();
    assert_eq!(
        encontrados.len(),
        OBJETOS_QUE_NO_CABEN_EN_UNA_PAGINA,
        "el listado devolvió {} objetos: sin paginar se quedaría en 1000",
        encontrados.len()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn las_claves_listadas_vienen_sin_el_prefijo_interno() {
    saltar_sin_docker!();
    let servidor = levantar_minio().await;
    let ctx = contexto(&servidor, "prefijo", "equipo/backups", PARTE_MB).await;
    let destino = destino(&ctx);
    let sockets = tempfile::tempdir().unwrap();

    let clave = "produccion/2026/08/21/x.age";
    poner(
        &destino,
        sockets.path(),
        "put",
        clave,
        b"artefacto".to_vec(),
    )
    .await
    .unwrap();

    // En el bucket la clave lleva el prefijo delante...
    let crudo = ctx
        .cliente
        .list_objects_v2()
        .bucket(&ctx.config.bucket)
        .send()
        .await
        .unwrap();
    assert_eq!(
        crudo.contents()[0].key(),
        Some("equipo/backups/produccion/2026/08/21/x.age")
    );

    // ...pero el núcleo nunca lo escribió, así que `List` se lo quita: una
    // clave con el prefijo puesto no sirve para volver a pedir el artefacto.
    let listado = destino
        .list(Request::new(ListRequest {
            prefix: "produccion/".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listado.artifacts.len(), 1);
    assert_eq!(listado.artifacts[0].key, clave);
    assert_eq!(listado.artifacts[0].size, 9);
    // Y la fecha en el formato que fija el `.proto`: RFC-3339 UTC.
    let fecha = &listado.artifacts[0].modified_at;
    assert_eq!(fecha.len(), 20, "«{fecha}» no es un RFC-3339 UTC");
    assert!(fecha.ends_with('Z'), "«{fecha}» no acaba en Z");

    // El artefacto se recupera con la clave que devolvió el listado.
    let recuperado = obtener(&destino, sockets.path(), "get", &listado.artifacts[0].key)
        .await
        .unwrap();
    assert_eq!(recuperado, b"artefacto");
}

#[tokio::test(flavor = "multi_thread")]
async fn borrar_algo_inexistente_no_es_un_error() {
    saltar_sin_docker!();
    let servidor = levantar_minio().await;
    let ctx = contexto(&servidor, "idempotente", "shieldbk", PARTE_MB).await;
    let destino = destino(&ctx);
    let sockets = tempfile::tempdir().unwrap();

    // La retención se reintenta, y un reintento que acierta —porque la pasada
    // anterior ya borró la mitad— no puede convertirse en un fallo.
    destino
        .delete(Request::new(DeleteRequest {
            key: "jamas-existio.age".into(),
        }))
        .await
        .unwrap();

    poner(
        &destino,
        sockets.path(),
        "put",
        "efimero.age",
        b"x".to_vec(),
    )
    .await
    .unwrap();
    for _ in 0..2 {
        destino
            .delete(Request::new(DeleteRequest {
                key: "efimero.age".into(),
            }))
            .await
            .unwrap();
    }
    assert!(
        admin::listar(&ctx, &ctx.config.clave(""))
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn un_fallo_a_mitad_de_subida_no_deja_partes_huerfanas() {
    saltar_sin_docker!();
    let servidor = levantar_minio().await;
    let ctx = contexto(&servidor, "huerfanas", "shieldbk", PARTE_MB).await;

    // Una fuente que entrega una parte entera y luego falla. El multipart llega
    // a abrirse —hace falta que se abra: es lo que se quiere ver abortado— y la
    // segunda lectura revienta.
    let fuente = FuenteQueFalla {
        datos: datos(5 * MIB),
        leidos: 0,
    };
    let clave = ctx.config.clave("rota.age");

    let contexto_tarea = ctx.clone();
    let clave_tarea = clave.clone();
    let e = con_progreso(move |mut progreso| async move {
        put::subir_desde(&contexto_tarea, &clave_tarea, fuente, &mut progreso).await
    })
    .await
    .unwrap_err();
    assert!(
        e.message().contains("canal de datos") || e.code() == Code::Unavailable,
        "la subida no falló por la fuente: {} ({:?})",
        e.message(),
        e.code()
    );

    // Lo que importa: las partes ya subidas no aparecen en un `ListObjects`
    // —el objeto no existe todavía— pero ocupan y **se facturan
    // indefinidamente**. Si el aborto no ocurrió, la subida sigue abierta.
    let abiertas = ctx
        .cliente
        .list_multipart_uploads()
        .bucket(&ctx.config.bucket)
        .send()
        .await
        .unwrap();
    assert!(
        abiertas.uploads().is_empty(),
        "quedaron {} subidas multipart abiertas tras el fallo: se facturan hasta que alguien las \
         quite",
        abiertas.uploads().len()
    );
    // Y el objeto no llegó a existir, que es lo correcto: se subió a medias.
    assert!(
        admin::listar(&ctx, &ctx.config.clave(""))
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn abortar_incompletos_limpia_una_subida_huerfana() {
    saltar_sin_docker!();
    let servidor = levantar_minio().await;
    let ctx = contexto(&servidor, "gc-huerfanas", "shieldbk", PARTE_MB).await;

    // Una subida abierta a mano, como la que deja un plugin que murió sin
    // llegar a abortar. Es lo que respalda `shieldbk storage gc`.
    let clave = ctx.config.clave("abandonada.age");
    ctx.cliente
        .create_multipart_upload()
        .bucket(&ctx.config.bucket)
        .key(&clave)
        .send()
        .await
        .unwrap();
    assert!(subida_abierta(&ctx, &clave).await.is_some());

    // Y otra fuera del prefijo del destino: un bucket puede estar compartido, y
    // abortar la subida de otro sería destruirle el backup a mitad.
    let ajena = "de-otro/tambien-abandonada.age";
    ctx.cliente
        .create_multipart_upload()
        .bucket(&ctx.config.bucket)
        .key(ajena)
        .send()
        .await
        .unwrap();

    let abortadas = admin::abortar_incompletos(&ctx, &ctx.config.clave(""))
        .await
        .unwrap();
    assert_eq!(abortadas, 1, "se abortó algo que no estaba bajo el prefijo");
    assert!(
        subida_abierta(&ctx, ajena).await.is_some(),
        "la limpieza se llevó por delante una subida ajena al prefijo"
    );
    assert!(
        subida_abierta(&ctx, &clave).await.is_none(),
        "la subida huérfana sigue abierta después de la limpieza"
    );

    // Y volver a limpiar no encuentra nada: la limpieza es repetible.
    assert_eq!(
        admin::abortar_incompletos(&ctx, &ctx.config.clave(""))
            .await
            .unwrap(),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn el_preflight_pasa_con_un_bucket_valido() {
    saltar_sin_docker!();
    let servidor = levantar_minio().await;
    let ctx = contexto(&servidor, "preflight-ok", "shieldbk", PARTE_MB).await;

    let pf = servicio(&ctx)
        .preflight(Request::new(PreflightRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert!(pf.ok, "{:?}", pf.checks);
    let nombres: Vec<&str> = pf.checks.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(nombres, vec!["bucket", "escritura", "listado"]);
    assert!(pf.server_version.contains(&servidor.endpoint));

    // El objeto de prueba se borra: el preflight no puede dejar residuo.
    assert!(
        admin::listar(&ctx, &ctx.config.clave(""))
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn el_preflight_detecta_un_bucket_inexistente() {
    saltar_sin_docker!();
    let servidor = levantar_minio().await;
    // Sin crear el bucket: es el error de configuración más común.
    let ctx = contexto_sin_bucket(&servidor, "no-existe", "shieldbk", PARTE_MB);

    let pf = servicio(&ctx)
        .preflight(Request::new(PreflightRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert!(!pf.ok);
    assert_eq!(pf.checks.len(), 3);
    for check in &pf.checks {
        assert!(!check.ok, "el check `{}` pasó sin bucket", check.name);
        // Un preflight que dice «falló» sin decir cómo arreglarlo no sirve de
        // nada: es el mensaje que ve el operador a las tres de la mañana.
        assert!(
            !check.remediation.is_empty(),
            "el check `{}` falló sin remedio",
            check.name
        );
        assert!(
            !check.detail.is_empty(),
            "el check `{}` falló sin detalle",
            check.name
        );
    }
}

// ---------------------------------------------------------------------------
// El ciclo completo por el binario de verdad
// ---------------------------------------------------------------------------

/// El plugin arrancado como proceso, con su canal de control ya abierto.
///
/// Mata **y recoge** el proceso al destruirse: un plugin al que no se le hace
/// `wait` queda zombie.
struct PluginVivo {
    hijo: Child,
    canal: Channel,
    ready: Ready,
    _sockets: TempDir,
}

impl PluginVivo {
    async fn arrancar() -> Self {
        let sockets = tempfile::tempdir().unwrap();
        let socket = sockets.path().join("control.sock");
        let pki = EphemeralPki::generate().unwrap();
        let sobre = Bootstrap::new(vec![1], socket.display().to_string(), pki.server_bundle());

        let mut hijo = Command::new(env!("CARGO_BIN_EXE_sb-plugin-r2"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        let mut entrada = hijo.stdin.take().unwrap();
        writeln!(entrada, "{}", sobre.to_line().unwrap()).unwrap();
        entrada.flush().unwrap();
        drop(entrada);

        let mut salida = BufReader::new(hijo.stdout.take().unwrap());
        let mut linea = String::new();
        salida.read_line(&mut linea).unwrap();
        let ready = Ready::from_line(&linea).unwrap();

        let canal = connect_control(&socket, pki.client_config().unwrap())
            .await
            .unwrap();

        Self {
            hijo,
            canal,
            ready,
            _sockets: sockets,
        }
    }
}

impl Drop for PluginVivo {
    fn drop(&mut self) {
        let _ = self.hijo.kill();
        let _ = self.hijo.wait();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn el_ciclo_completo_por_el_plugin_real() {
    saltar_sin_docker!();
    let servidor = levantar_minio().await;
    // El bucket se crea con un cliente aparte: el plugin no crea buckets, los
    // usa.
    let ctx = contexto(&servidor, "ciclo", "shieldbk", PARTE_MB).await;

    let vivo = PluginVivo::arrancar().await;
    assert_eq!(vivo.ready.protocol_version, 1);
    assert_eq!(vivo.ready.capabilities, vec!["storage"]);
    assert!(vivo.ready.pid > 0);

    PluginClient::new(vivo.canal.clone())
        .configure(ConfigureRequest {
            config: valores(&servidor.endpoint, "ciclo", "shieldbk", PARTE_MB),
        })
        .await
        .unwrap();

    let pf = PluginClient::new(vivo.canal.clone())
        .preflight(PreflightRequest {})
        .await
        .unwrap()
        .into_inner();
    assert!(pf.ok, "{:?}", pf.checks);

    let sockets = tempfile::tempdir().unwrap();
    let mut destino = StorageClient::new(vivo.canal.clone());

    // Put: los bytes viajan por el socket Unix, no por gRPC. Multiparte, para
    // que el ciclo real ejercite el camino delicado y no solo el fácil.
    let contenido = datos(MULTIPARTE);
    let canal = DataChannel::create(sockets.path(), "put").unwrap();
    let ruta = canal.path().display().to_string();
    let mut flujo = destino
        .put(PutRequest {
            key: "produccion/backup.age".into(),
            data_socket: ruta,
        })
        .await
        .unwrap()
        .into_inner();
    let copia = contenido.clone();
    let escritura = tokio::spawn(async move {
        let mut s = canal.accept().await.unwrap();
        s.write_all(&copia).await.unwrap();
        s.shutdown().await.unwrap();
    });
    let mut ultimo = 0;
    while let Some(p) = flujo.message().await.unwrap() {
        ultimo = usize::try_from(p.bytes).unwrap();
    }
    escritura.await.unwrap();
    assert_eq!(ultimo, MULTIPARTE);

    // Get: y de vuelta, byte a byte.
    let canal = DataChannel::create(sockets.path(), "get").unwrap();
    let ruta = canal.path().display().to_string();
    let mut flujo = destino
        .get(GetRequest {
            key: "produccion/backup.age".into(),
            data_socket: ruta,
        })
        .await
        .unwrap()
        .into_inner();
    let lectura = tokio::spawn(async move {
        let mut s = canal.accept().await.unwrap();
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut s, &mut buf)
            .await
            .unwrap();
        buf
    });
    while flujo.message().await.unwrap().is_some() {}
    assert_eq!(lectura.await.unwrap(), contenido);

    // List: con la clave sin el prefijo interno.
    let listado = destino
        .list(ListRequest {
            prefix: "produccion/".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listado.artifacts.len(), 1);
    assert_eq!(listado.artifacts[0].key, "produccion/backup.age");
    assert_eq!(
        listado.artifacts[0].size,
        u64::try_from(MULTIPARTE).unwrap()
    );

    // Delete: y el destino se queda vacío.
    destino
        .delete(DeleteRequest {
            key: "produccion/backup.age".into(),
        })
        .await
        .unwrap();
    assert!(
        admin::listar(&ctx, &ctx.config.clave(""))
            .await
            .unwrap()
            .is_empty()
    );
}
