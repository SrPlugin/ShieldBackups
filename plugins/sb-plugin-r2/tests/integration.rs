// The `clippy.toml` exception for `unwrap` covers `#[test]` bodies, but this
// whole file is test code: bringing up the container, assembling the context
// and the put/get helpers are too, and there an `unwrap` is exactly what is
// wanted -- for the test to blow up where it failed, with its line number.
#![allow(clippy::unwrap_used)]

//! The R2 plugin, against a real object server.
//!
//! Up to here everything this plugin covered were pure functions. Nothing had
//! ever talked to a server, and the things that most easily break in a storage
//! target -- the listing's pagination, the size of a multipart's parts, the
//! upload left open after a failure -- **cannot be seen without one**: a
//! truncated listing does not give an error, it gives a short list.
//!
//! ## Why `MinIO`
//!
//! `MinIO` speaks the S3 protocol and runs in Docker, so it exercises the whole
//! plugin without Cloudflare credentials, at no cost and without the network.
//! With it, what belongs to S3 is tested, which is almost everything.
//!
//! **What `MinIO` does not validate** is R2's own rule: every part of a
//! multipart except the last must be the same size. `MinIO` tolerates uneven
//! parts, so a plugin that produced them would pass these tests and fail in
//! production. That is why
//! [`every_part_of_a_multipart_is_the_same_size_except_the_last`] looks at the
//! sizes itself, instead of trusting the server to reject them. Checking
//! against real R2 is left for another task.
//!
//! ## Docker
//!
//! Without Docker there is no server and these tests skip themselves, saying so
//! on stderr. A test that cannot be run must not fail everyone's build, but it
//! must not pass silently either.

use std::collections::HashMap;
use std::future::Future;
use std::io::{BufRead as _, BufReader, Write as _};
use std::path::Path;
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::task::{Context as TaskContext, Poll};

use sb_plugin_r2::client::{self, Context, State};
use sb_plugin_r2::config::R2Config;
use sb_plugin_r2::plugin::R2Plugin;
use sb_plugin_r2::storage::R2Storage;
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

/// One mebibyte, which is the unit a multipart part is measured in.
const MIB: usize = 1024 * 1024;

/// Part size the multiparts are tested with: the protocol's minimum. The
/// smaller the part, the more parts come out of an object that fits in a test
/// without taking a minute.
const PART_MB: i64 = 5;

/// Multipart test object: 17 MiB with 5 MiB parts are **three whole parts and a
/// 2 MiB remainder**. The remainder is what matters: an object measuring an
/// exact multiple would not tell a correct chunker from one that loses or
/// repeats the last part.
const MULTIPART: usize = 17 * MIB;

// ---------------------------------------------------------------------------
// Docker
// ---------------------------------------------------------------------------

/// Whether there is a container daemon testcontainers can talk to.
///
/// It is asked only once: `docker info` takes its time and these tests are
/// thirteen.
fn has_docker() -> bool {
    static AVAILABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        Command::new("docker")
            .args(["info", "--format", "{{.ServerVersion}}"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    })
}

/// The name of the test currently running, for the skip message.
macro_rules! function_name {
    () => {{
        fn f() {}
        let name = std::any::type_name_of_val(&f);
        // `integration::the_test::{{closure}}::f` -> `the_test`. The
        // `{{closure}}` bits are added by `#[tokio::test]`, which wraps the
        // test's body in a future; the useful name is the last segment that is
        // not one of those.
        name.strip_suffix("::f")
            .unwrap_or(name)
            .rsplit("::")
            .find(|segment| !segment.starts_with("{{"))
            .unwrap_or(name)
    }};
}

/// Leaves the test without failing if there is no Docker, saying why.
///
/// A fixed `#[ignore]` would hide these tests even where they can be run; a
/// hard failure would break the build for anyone without Docker. The warning on
/// stderr is what keeps a skip from passing for a green.
macro_rules! skip_without_docker {
    () => {
        if !has_docker() {
            eprintln!(
                "SKIPPED {}::{}: no Docker available, so the MinIO the R2 plugin is tested \
                 against cannot be started. Start Docker and run it again.",
                module_path!(),
                function_name!()
            );
            return;
        }
    };
}

// ---------------------------------------------------------------------------
// The server and the plugin's context
// ---------------------------------------------------------------------------

/// A started `MinIO`, with its endpoint already resolved.
///
/// The container is kept inside: when the `Server` is dropped, testcontainers
/// stops and removes the container. Each test brings up its own so that none
/// sees what another left in the bucket.
struct Server {
    _container: ContainerAsync<MinIO>,
    endpoint: String,
}

/// Default credentials of the `MinIO` image. They are not a secret: the server
/// lives inside an ephemeral container and only listens on localhost.
const USER: &str = "minioadmin";
const PASSWORD: &str = "minioadmin";

async fn start_minio() -> Server {
    let container = MinIO::default().start().await.unwrap();
    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(9000).await.unwrap();
    Server {
        endpoint: format!("http://{host}:{port}"),
        _container: container,
    }
}

fn text(value: &str) -> Value {
    Value {
        kind: Some(Kind::StringValue(value.to_string())),
    }
}

fn integer(value: i64) -> Value {
    Value {
        kind: Some(Kind::IntValue(value)),
    }
}

/// The configuration the core would send through `Configure`, pointing at
/// `MinIO`.
///
/// `max_object_gb` is set to 1 GB **on purpose**: with 5 MiB parts and the cap
/// of 10 000 parts only about 52 GB are reachable, so the default value of
/// 640 GB would make `Configure` reject this configuration. That is the early
/// validation in `config.rs` doing its job.
fn values(endpoint: &str, bucket: &str, prefix: &str, part_mb: i64) -> HashMap<String, Value> {
    HashMap::from([
        // The `account_id` is only used to derive the endpoint, and here the
        // endpoint comes explicitly: this field exists precisely so a local
        // MinIO can be pointed at.
        ("account_id".to_string(), text("test-account")),
        ("bucket".to_string(), text(bucket)),
        ("access_key_id".to_string(), text(USER)),
        ("secret_access_key".to_string(), text(PASSWORD)),
        ("endpoint".to_string(), text(endpoint)),
        ("prefix".to_string(), text(prefix)),
        ("part_size_mb".to_string(), integer(part_mb)),
        ("max_object_gb".to_string(), integer(1)),
        ("concurrency".to_string(), integer(4)),
    ])
}

/// A plugin context pointing at the server, with the bucket already created.
async fn context(server: &Server, bucket: &str, prefix: &str, part_mb: i64) -> Context {
    let context = context_without_bucket(server, bucket, prefix, part_mb);
    context
        .client
        .create_bucket()
        .bucket(bucket)
        .send()
        .await
        .unwrap();
    context
}

/// The same, but without creating the bucket: the preflight that must fail
/// needs it.
fn context_without_bucket(server: &Server, bucket: &str, prefix: &str, part_mb: i64) -> Context {
    let config = R2Config::from_values(&values(&server.endpoint, bucket, prefix, part_mb)).unwrap();
    let client = client::build(&config);
    Context { config, client }
}

/// The storage target, mounted on an already configured context.
fn storage(context: &Context) -> R2Storage {
    let state = State::new("r2");
    state.store(context.clone());
    R2Storage::new(state)
}

/// The `Plugin` service, already configured.
fn service(context: &Context) -> R2Plugin {
    let state = State::new("r2");
    state.store(context.clone());
    R2Plugin::new(state)
}

/// Runs a job that needs a [`ProgressEmitter`] and returns its result.
///
/// A `ProgressEmitter` is only created by `progress_stream`, because an emitter
/// with no stream on the other side would emit to nobody. This function does
/// what the core does: consume the stream to the end and keep the error if
/// there was one.
async fn with_progress<F, Fut>(job: F) -> Result<(), Status>
where
    F: FnOnce(ProgressEmitter) -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), Status>> + Send + 'static,
{
    let mut receiver = progress_stream(job).into_inner().into_inner();
    let mut result = Ok(());
    while let Some(message) = receiver.recv().await {
        if let Err(e) = message {
            result = Err(e);
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Put and Get through the storage target, with its data channel
// ---------------------------------------------------------------------------

/// Consumes a data RPC's progress stream to the end.
async fn drain_stream(stream: sb_plugin_sdk::ProgressStream) -> Result<(), Status> {
    let mut receiver = stream.into_inner();
    while let Some(message) = receiver.recv().await {
        message?;
    }
    Ok(())
}

/// Stores `content` under `key` going through the storage target and its data
/// channel.
async fn put(
    storage: &R2Storage,
    sockets: &Path,
    name: &str,
    key: &str,
    content: Vec<u8>,
) -> Result<(), Status> {
    let channel = DataChannel::create(sockets, name).unwrap();
    let path = channel.path().display().to_string();
    let stream = storage
        .put(Request::new(PutRequest {
            key: key.to_string(),
            data_socket: path,
        }))
        .await?
        .into_inner();

    let writer = tokio::spawn(async move {
        let mut s = channel.accept().await.unwrap();
        s.write_all(&content).await.unwrap();
        s.shutdown().await.unwrap();
    });
    let result = drain_stream(stream).await;
    // If the upload failed, the writer gets a `BrokenPipe` and panics: the
    // error to show is the first one, not the knock-on one.
    match result {
        Ok(()) => {
            writer.await.unwrap();
            Ok(())
        }
        Err(e) => {
            writer.abort();
            Err(e)
        }
    }
}

/// Retrieves what was stored under `key`.
async fn get(
    storage: &R2Storage,
    sockets: &Path,
    name: &str,
    key: &str,
) -> Result<Vec<u8>, Status> {
    let channel = DataChannel::create(sockets, name).unwrap();
    let path = channel.path().display().to_string();
    let stream = storage
        .get(Request::new(GetRequest {
            key: key.to_string(),
            data_socket: path,
        }))
        .await?
        .into_inner();

    let reader = tokio::spawn(async move {
        let mut s = channel.accept().await.unwrap();
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut s, &mut buf)
            .await
            .unwrap();
        buf
    });
    drain_stream(stream).await?;
    Ok(reader.await.unwrap())
}

/// Deterministic, non-repetitive bytes: that way a part that is lost, repeated
/// or misplaced changes the content and not just the size.
fn data(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| u8::try_from((i * 31 + i / 251) % 256).unwrap_or(0))
        .collect()
}

// ---------------------------------------------------------------------------
// Artificial data sources, for what a socket cannot do
// ---------------------------------------------------------------------------

/// A source that delivers some bytes and **then fails**.
///
/// It exists because a Unix socket does not know how to fail: closing it is a
/// clean end of stream, not an error, and a failure halfway through an upload
/// is exactly what has to be provoked to see whether the multipart gets
/// aborted.
struct FailingSource {
    data: Vec<u8>,
    read: usize,
}

impl AsyncRead for FailingSource {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.read >= self.data.len() {
            return Poll::Ready(Err(std::io::Error::other(
                "the data source broke halfway through the upload",
            )));
        }
        let how_many = buf.remaining().min(self.data.len() - self.read);
        let from = self.read;
        buf.put_slice(&self.data[from..from + how_many]);
        self.read += how_many;
        Poll::Ready(Ok(()))
    }
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn it_uploads_and_downloads_a_small_object() {
    skip_without_docker!();
    let server = start_minio().await;
    let ctx = context(&server, "small", "shieldbk", PART_MB).await;
    let storage = storage(&ctx);
    let sockets = tempfile::tempdir().unwrap();

    let content = data(4096);
    put(
        &storage,
        sockets.path(),
        "put",
        "production/backup.age",
        content.clone(),
    )
    .await
    .unwrap();

    let retrieved = get(&storage, sockets.path(), "get", "production/backup.age")
        .await
        .unwrap();
    assert_eq!(retrieved, content);
}

#[tokio::test(flavor = "multi_thread")]
async fn it_uploads_and_downloads_a_real_multipart_object() {
    skip_without_docker!();
    let server = start_minio().await;
    let ctx = context(&server, "multipart", "shieldbk", PART_MB).await;
    let storage = storage(&ctx);
    let sockets = tempfile::tempdir().unwrap();

    // 17 MiB with 5 MiB parts: three whole ones and a 2 MiB remainder.
    let content = data(MULTIPART);
    put(
        &storage,
        sockets.path(),
        "put",
        "large.age",
        content.clone(),
    )
    .await
    .unwrap();

    let retrieved = get(&storage, sockets.path(), "get", "large.age")
        .await
        .unwrap();
    // Byte for byte, not just the size: a chunker that misplaced the parts
    // would return exactly the same bytes in total.
    assert_eq!(retrieved.len(), MULTIPART);
    assert_eq!(
        retrieved, content,
        "the multipart object did not come back the same"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn every_part_of_a_multipart_is_the_same_size_except_the_last() {
    skip_without_docker!();
    let server = start_minio().await;
    let ctx = context(&server, "parts", "shieldbk", PART_MB).await;
    let storage = storage(&ctx);
    let sockets = tempfile::tempdir().unwrap();

    // The 17 MiB are written into the channel **without closing it**: the
    // plugin uploads the three whole parts and sits waiting for the rest of the
    // fourth. That is where the parts can be looked at, which is before
    // completing the multipart and therefore before they stop existing
    // separately.
    let channel = DataChannel::create(sockets.path(), "put").unwrap();
    let path = channel.path().display().to_string();
    let key = "uniform.age";
    let stream = storage
        .put(Request::new(PutRequest {
            key: key.to_string(),
            data_socket: path,
        }))
        .await
        .unwrap()
        .into_inner();

    let content = data(MULTIPART);
    let copy = content.clone();
    let writer = tokio::spawn(async move {
        let mut s = channel.accept().await.unwrap();
        s.write_all(&copy).await.unwrap();
        // No `shutdown`: the channel closes when the stream is dropped, and
        // that happens when this task ends. It is returned so it can be dropped
        // by hand.
        s
    });

    let whole = PART_MB * i64::try_from(MIB).unwrap();
    let sizes = wait_for_parts(&ctx, &ctx.config.key(key), 3).await;
    assert_eq!(sizes.len(), 3);
    for (i, size) in sizes.iter().enumerate() {
        assert_eq!(
            *size,
            whole,
            "part {} is {size} and not {whole}: R2 requires every part except the last to be the \
             same size, and MinIO tolerates it without complaining",
            i + 1
        );
    }

    // The channel is dropped: the plugin sees the end of stream, uploads the
    // last part and completes the multipart.
    drop(writer.await.unwrap());
    drain_stream(stream).await.unwrap();

    let retrieved = get(&storage, sockets.path(), "get", key).await.unwrap();
    assert_eq!(retrieved, content);
}

/// Waits until `key`'s multipart upload has at least `how_many` parts and
/// returns their sizes, sorted by part number.
///
/// It polls because the parts travel over the network: there is no instant at
/// which they are guaranteed, only one from which on they are.
async fn wait_for_parts(context: &Context, key: &str, how_many: usize) -> Vec<i64> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        if let Some(id) = open_upload(context, key).await {
            let parts = context
                .client
                .list_parts()
                .bucket(&context.config.bucket)
                .key(key)
                .upload_id(&id)
                .send()
                .await
                .unwrap();
            let mut found: Vec<(i32, i64)> = parts
                .parts()
                .iter()
                .map(|p| (p.part_number().unwrap_or(0), p.size().unwrap_or(0)))
                .collect();
            if found.len() >= how_many {
                found.sort_by_key(|(number, _)| *number);
                return found.into_iter().map(|(_, size)| size).collect();
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the first {how_many} parts of `{key}` did not show up in 60 s"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

/// The `upload_id` of `key`'s open upload, if there is one.
async fn open_upload(context: &Context, key: &str) -> Option<String> {
    context
        .client
        .list_multipart_uploads()
        .bucket(&context.config.bucket)
        .send()
        .await
        .unwrap()
        .uploads()
        .iter()
        .find(|s| s.key() == Some(key))
        .and_then(|s| s.upload_id().map(ToString::to_string))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_zero_byte_object_is_uploaded_and_downloaded() {
    skip_without_docker!();
    let server = start_minio().await;
    let ctx = context(&server, "empty", "shieldbk", PART_MB).await;
    let storage = storage(&ctx);
    let sockets = tempfile::tempdir().unwrap();

    // An empty artifact is legitimate -- a dump of a database with no data --
    // and it is the case where a naive chunker emits no part at all and the
    // object never comes to exist.
    put(&storage, sockets.path(), "put", "empty.age", Vec::new())
        .await
        .unwrap();

    let retrieved = get(&storage, sockets.path(), "get", "empty.age")
        .await
        .unwrap();
    assert!(retrieved.is_empty());

    // And it really exists, with size zero: it is not that the listing hides
    // it.
    let listing = admin::list(&ctx, &ctx.config.key("")).await.unwrap();
    assert_eq!(listing.len(), 1);
    assert_eq!(listing[0].key, "empty.age");
    assert_eq!(listing[0].size, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn downloading_a_nonexistent_key_yields_not_found() {
    skip_without_docker!();
    let server = start_minio().await;
    let ctx = context(&server, "absent", "shieldbk", PART_MB).await;
    let storage = storage(&ctx);
    let sockets = tempfile::tempdir().unwrap();

    // `not_found` and not a generic error: whoever restores has to be able to
    // tell "that artifact does not exist" from "the transfer was cut off".
    let e = get(&storage, sockets.path(), "get", "never-existed.age")
        .await
        .unwrap_err();
    assert_eq!(e.code(), Code::NotFound, "{}", e.message());
    assert!(
        e.message().contains("never-existed.age"),
        "the error does not say which key was missing: {}",
        e.message()
    );
}

/// One thousand and fifty: `ListObjectsV2` returns at most 1000 per page, so a
/// storage target that kept only the first one would return 1000 and **nobody
/// would notice**. It would not give an error: it would give a short list, with
/// which `verify --all` would say everything is fine after looking at only the
/// first thousand.
const OBJECTS_THAT_DO_NOT_FIT_IN_ONE_PAGE: usize = 1050;

#[tokio::test(flavor = "multi_thread")]
async fn the_listing_paginates_beyond_a_thousand_objects() {
    skip_without_docker!();
    let server = start_minio().await;
    let ctx = context(&server, "paginated", "shieldbk", PART_MB).await;

    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..OBJECTS_THAT_DO_NOT_FIT_IN_ONE_PAGE {
        let client = ctx.client.clone();
        let bucket = ctx.config.bucket.clone();
        let key = ctx.config.key(&format!("batch/{i:05}.age"));
        tasks.spawn(async move {
            client
                .put_object()
                .bucket(bucket)
                .key(key)
                .body(aws_sdk_s3::primitives::ByteStream::from_static(b"x"))
                .send()
                .await
                .unwrap();
        });
        // In parallel, but bounded: a thousand requests at once would exhaust
        // the connection pool before the server.
        while tasks.len() >= 32 {
            tasks.join_next().await.unwrap().unwrap();
        }
    }
    while let Some(t) = tasks.join_next().await {
        t.unwrap();
    }

    let found = admin::list(&ctx, &ctx.config.key("")).await.unwrap();
    assert_eq!(
        found.len(),
        OBJECTS_THAT_DO_NOT_FIT_IN_ONE_PAGE,
        "the listing returned {} objects: without paginating it would stop at 1000",
        found.len()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_listed_keys_come_without_the_internal_prefix() {
    skip_without_docker!();
    let server = start_minio().await;
    let ctx = context(&server, "prefix", "team/backups", PART_MB).await;
    let storage = storage(&ctx);
    let sockets = tempfile::tempdir().unwrap();

    let key = "production/2026/08/21/x.age";
    put(&storage, sockets.path(), "put", key, b"artifact".to_vec())
        .await
        .unwrap();

    // In the bucket the key carries the prefix in front...
    let raw = ctx
        .client
        .list_objects_v2()
        .bucket(&ctx.config.bucket)
        .send()
        .await
        .unwrap();
    assert_eq!(
        raw.contents()[0].key(),
        Some("team/backups/production/2026/08/21/x.age")
    );

    // ...but the core never wrote it, so `List` strips it: a key with the
    // prefix attached is useless for requesting the artifact again.
    let listing = storage
        .list(Request::new(ListRequest {
            prefix: "production/".into(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listing.artifacts.len(), 1);
    assert_eq!(listing.artifacts[0].key, key);
    assert_eq!(listing.artifacts[0].size, 8);
    // And the date in the format the `.proto` fixes: RFC-3339 UTC.
    let date = &listing.artifacts[0].modified_at;
    assert_eq!(date.len(), 20, "`{date}` is not an RFC-3339 UTC");
    assert!(date.ends_with('Z'), "`{date}` does not end in Z");

    // The artifact is retrieved with the key the listing returned.
    let retrieved = get(&storage, sockets.path(), "get", &listing.artifacts[0].key)
        .await
        .unwrap();
    assert_eq!(retrieved, b"artifact");
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_something_nonexistent_is_not_an_error() {
    skip_without_docker!();
    let server = start_minio().await;
    let ctx = context(&server, "idempotent", "shieldbk", PART_MB).await;
    let storage = storage(&ctx);
    let sockets = tempfile::tempdir().unwrap();

    // Retention is retried, and a retry that succeeds -- because the previous
    // pass already deleted half of it -- cannot turn into a failure.
    storage
        .delete(Request::new(DeleteRequest {
            key: "never-existed.age".into(),
        }))
        .await
        .unwrap();

    put(
        &storage,
        sockets.path(),
        "put",
        "ephemeral.age",
        b"x".to_vec(),
    )
    .await
    .unwrap();
    for _ in 0..2 {
        storage
            .delete(Request::new(DeleteRequest {
                key: "ephemeral.age".into(),
            }))
            .await
            .unwrap();
    }
    assert!(
        admin::list(&ctx, &ctx.config.key(""))
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failure_halfway_through_an_upload_leaves_no_orphaned_parts() {
    skip_without_docker!();
    let server = start_minio().await;
    let ctx = context(&server, "orphans", "shieldbk", PART_MB).await;

    // A source that delivers one whole part and then fails. The multipart does
    // get opened -- it has to be: that is what we want to see aborted -- and
    // the second read blows up.
    let source = FailingSource {
        data: data(5 * MIB),
        read: 0,
    };
    let key = ctx.config.key("broken.age");

    let task_context = ctx.clone();
    let task_key = key.clone();
    let e = with_progress(move |mut progress| async move {
        put::upload_from(&task_context, &task_key, source, &mut progress).await
    })
    .await
    .unwrap_err();
    assert!(
        e.message().contains("data channel") || e.code() == Code::Unavailable,
        "the upload did not fail because of the source: {} ({:?})",
        e.message(),
        e.code()
    );

    // What matters: the parts already uploaded do not show up in a
    // `ListObjects` -- the object does not exist yet -- but they take up space
    // and **are billed indefinitely**. If the abort did not happen, the upload
    // is still open.
    let open = ctx
        .client
        .list_multipart_uploads()
        .bucket(&ctx.config.bucket)
        .send()
        .await
        .unwrap();
    assert!(
        open.uploads().is_empty(),
        "{} multipart uploads were left open after the failure: they are billed until somebody \
         removes them",
        open.uploads().len()
    );
    // And the object never came to exist, which is right: it was only half
    // uploaded.
    assert!(
        admin::list(&ctx, &ctx.config.key(""))
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn abort_incomplete_cleans_up_an_orphaned_upload() {
    skip_without_docker!();
    let server = start_minio().await;
    let ctx = context(&server, "gc-orphans", "shieldbk", PART_MB).await;

    // An upload opened by hand, like the one a plugin that died before aborting
    // leaves behind. It is what backs `shieldbk storage gc`.
    let key = ctx.config.key("abandoned.age");
    ctx.client
        .create_multipart_upload()
        .bucket(&ctx.config.bucket)
        .key(&key)
        .send()
        .await
        .unwrap();
    assert!(open_upload(&ctx, &key).await.is_some());

    // And another one outside the target's prefix: a bucket may be shared, and
    // aborting somebody else's upload would destroy their backup halfway
    // through.
    let foreign = "someone-else/also-abandoned.age";
    ctx.client
        .create_multipart_upload()
        .bucket(&ctx.config.bucket)
        .key(foreign)
        .send()
        .await
        .unwrap();

    let aborted = admin::abort_incomplete(&ctx, &ctx.config.key(""))
        .await
        .unwrap();
    assert_eq!(aborted, 1, "something not under the prefix was aborted");
    assert!(
        open_upload(&ctx, foreign).await.is_some(),
        "the cleanup took down an upload foreign to the prefix"
    );
    assert!(
        open_upload(&ctx, &key).await.is_none(),
        "the orphaned upload is still open after the cleanup"
    );

    // And cleaning up again finds nothing: the cleanup is repeatable.
    assert_eq!(
        admin::abort_incomplete(&ctx, &ctx.config.key(""))
            .await
            .unwrap(),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_preflight_passes_with_a_valid_bucket() {
    skip_without_docker!();
    let server = start_minio().await;
    let ctx = context(&server, "preflight-ok", "shieldbk", PART_MB).await;

    let pf = service(&ctx)
        .preflight(Request::new(PreflightRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert!(pf.ok, "{:?}", pf.checks);
    let names: Vec<&str> = pf.checks.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, vec!["bucket", "write", "list"]);
    assert!(pf.server_version.contains(&server.endpoint));

    // The probe object is deleted: the preflight must leave no leftovers.
    assert!(
        admin::list(&ctx, &ctx.config.key(""))
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_preflight_detects_a_nonexistent_bucket() {
    skip_without_docker!();
    let server = start_minio().await;
    // Without creating the bucket: it is the most common configuration error.
    let ctx = context_without_bucket(&server, "does-not-exist", "shieldbk", PART_MB);

    let pf = service(&ctx)
        .preflight(Request::new(PreflightRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert!(!pf.ok);
    assert_eq!(pf.checks.len(), 3);
    for check in &pf.checks {
        assert!(
            !check.ok,
            "the check `{}` passed with no bucket",
            check.name
        );
        // A preflight that says "it failed" without saying how to fix it is
        // useless: it is the message the operator sees at three in the morning.
        assert!(
            !check.remediation.is_empty(),
            "the check `{}` failed with no remedy",
            check.name
        );
        assert!(
            !check.detail.is_empty(),
            "the check `{}` failed with no detail",
            check.name
        );
    }
}

// ---------------------------------------------------------------------------
// The full cycle through the real binary
// ---------------------------------------------------------------------------

/// The plugin started as a process, with its control channel already open.
///
/// It kills **and reaps** the process when dropped: a plugin that is never
/// `wait`ed on becomes a zombie.
struct LivePlugin {
    child: Child,
    channel: Channel,
    ready: Ready,
    _sockets: TempDir,
}

impl LivePlugin {
    async fn start() -> Self {
        let sockets = tempfile::tempdir().unwrap();
        let socket = sockets.path().join("control.sock");
        let pki = EphemeralPki::generate().unwrap();
        let envelope = Bootstrap::new(vec![1], socket.display().to_string(), pki.server_bundle());

        let mut child = Command::new(env!("CARGO_BIN_EXE_sb-plugin-r2"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        let mut input = child.stdin.take().unwrap();
        writeln!(input, "{}", envelope.to_line().unwrap()).unwrap();
        input.flush().unwrap();
        drop(input);

        let mut output = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        let ready = Ready::from_line(&line).unwrap();

        let channel = connect_control(&socket, pki.client_config().unwrap())
            .await
            .unwrap();

        Self {
            child,
            channel,
            ready,
            _sockets: sockets,
        }
    }
}

impl Drop for LivePlugin {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_full_cycle_through_the_real_plugin() {
    skip_without_docker!();
    let server = start_minio().await;
    // The bucket is created with a separate client: the plugin does not create
    // buckets, it uses them.
    let ctx = context(&server, "cycle", "shieldbk", PART_MB).await;

    let live = LivePlugin::start().await;
    assert_eq!(live.ready.protocol_version, 1);
    assert_eq!(live.ready.capabilities, vec!["storage"]);
    assert!(live.ready.pid > 0);

    PluginClient::new(live.channel.clone())
        .configure(ConfigureRequest {
            config: values(&server.endpoint, "cycle", "shieldbk", PART_MB),
        })
        .await
        .unwrap();

    let pf = PluginClient::new(live.channel.clone())
        .preflight(PreflightRequest {})
        .await
        .unwrap()
        .into_inner();
    assert!(pf.ok, "{:?}", pf.checks);

    let sockets = tempfile::tempdir().unwrap();
    let mut storage = StorageClient::new(live.channel.clone());

    // Put: the bytes travel over the Unix socket, not over gRPC. Multipart, so
    // that the real cycle exercises the delicate path and not just the easy
    // one.
    let content = data(MULTIPART);
    let channel = DataChannel::create(sockets.path(), "put").unwrap();
    let path = channel.path().display().to_string();
    let mut stream = storage
        .put(PutRequest {
            key: "production/backup.age".into(),
            data_socket: path,
        })
        .await
        .unwrap()
        .into_inner();
    let copy = content.clone();
    let writer = tokio::spawn(async move {
        let mut s = channel.accept().await.unwrap();
        s.write_all(&copy).await.unwrap();
        s.shutdown().await.unwrap();
    });
    let mut last = 0;
    while let Some(p) = stream.message().await.unwrap() {
        last = usize::try_from(p.bytes).unwrap();
    }
    writer.await.unwrap();
    assert_eq!(last, MULTIPART);

    // Get: and back again, byte for byte.
    let channel = DataChannel::create(sockets.path(), "get").unwrap();
    let path = channel.path().display().to_string();
    let mut stream = storage
        .get(GetRequest {
            key: "production/backup.age".into(),
            data_socket: path,
        })
        .await
        .unwrap()
        .into_inner();
    let reader = tokio::spawn(async move {
        let mut s = channel.accept().await.unwrap();
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut s, &mut buf)
            .await
            .unwrap();
        buf
    });
    while stream.message().await.unwrap().is_some() {}
    assert_eq!(reader.await.unwrap(), content);

    // List: with the key stripped of the internal prefix.
    let listing = storage
        .list(ListRequest {
            prefix: "production/".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listing.artifacts.len(), 1);
    assert_eq!(listing.artifacts[0].key, "production/backup.age");
    assert_eq!(listing.artifacts[0].size, u64::try_from(MULTIPART).unwrap());

    // Delete: and the storage target is left empty.
    storage
        .delete(DeleteRequest {
            key: "production/backup.age".into(),
        })
        .await
        .unwrap();
    assert!(
        admin::list(&ctx, &ctx.config.key(""))
            .await
            .unwrap()
            .is_empty()
    );
}
