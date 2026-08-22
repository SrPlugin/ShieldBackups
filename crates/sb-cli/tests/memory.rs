// Just as in the rest of the workspace's tests: here an `unwrap` is what is
// wanted, for the test to blow up exactly where it failed. These helpers are
// free functions of a `tests/` file, so the `clippy.toml` allowance -- which
// only reaches `#[test]` and `#[cfg(test)]` -- does not get to them and has to
// be granted at file level.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Is it true that memory does not depend on the size of the backup?
//!
//! The whole design of `ShieldBackups` rests on one promise: backing up a
//! 400 GB database uses the same RAM as backing up a 2 GB one, because nothing
//! accumulates -- the dump goes from the source to the storage target crossing
//! zstd and age in streaming. It is the promise that allows promising a
//! container with a low limit. This file measures it instead of believing it.
//!
//! # How it is measured
//!
//! Without `unsafe`, which the workspace forbids: `getrusage` would require
//! `libc`, so `/proc` is read instead. `shieldbk` is launched as a child and a
//! thread samples every 25 ms the `/proc/<pid>/status` of the core **and of all
//! its descendants**, which are the plugin processes. Measuring only the core
//! would not do: if the core stays flat but the plugin accumulates, the promise
//! is just as broken.
//!
//! Two figures are read from each process:
//!
//! - `VmRSS`, the **instantaneous** residency. Sampling it can miss the peak if
//!   it happens between two samples.
//! - `VmHWM`, the **historical** peak the Linux kernel keeps itself. It never
//!   goes down, so keeping the maximum of the readings gives the real peak as
//!   long as it was read at least once near the end.
//!
//! Both are reported and compared: if they differ much, the sampling is missing
//! the peak and `VmHWM` is the one to trust. The size assertions use `VmHWM`,
//! which is the conservative figure; the `--jobs` one uses the maximum of
//! `core + plugins` **within a single sample**, because there the plugins take
//! turns and adding historical peaks that never coincided would inflate the
//! baseline.
//!
//! # What this does NOT cover
//!
//! It is measured against `sb-plugin-mock`, whose storage target writes the
//! artifact in one go into a file. **`sb-plugin-r2`'s multipart chunker is not
//! covered here**, and it is the system's biggest RAM consumer: its expected
//! ceiling is `part_size x concurrency`, 64 MiB x 4 = 256 MiB by default
//! (`plugins/sb-plugin-r2/src/put.rs`). These figures measure the core and the
//! data path; the budget of a container uploading to R2 has to add that ceiling
//! on top.
//!
//! # How they are run
//!
//! They are all marked `#[ignore]`: they move gigabytes across the disk and
//! cannot run on every push. The four together take about 21 s in release --
//! less than the volume suggests, because the pipeline runs at ~400 MiB/s --
//! but in debug they take several minutes.
//!
//! ```text
//! cargo test --release --test memory -- --ignored --nocapture
//! ```
//!
//! **In release.** The debug profile allocates differently -- no inlining, with
//! zstd's and age's buffers unoptimised -- and its figures do not represent
//! what runs in production. `--nocapture` is what makes the figures visible;
//! without it the test says "ok" and shows nothing, which is exactly the
//! opposite of what is wanted from these tests.
//!
//! # Measured baseline
//!
//! Measured on 2026-08-21 on `x86_64`, Linux 6.17, 16 cores, `release` profile,
//! the `rustc` from `rust-toolchain.toml`. Figures in MiB: "core" and "plugins"
//! are `VmHWM`; "at once" is the maximum of `core + plugins` within a single
//! sample, which is what has to fit in the container's limit.
//!
//! | Scenario                        |   Core | Plugins |  At once |
//! |---------------------------------|-------:|--------:|---------:|
//! | backup 64 MiB                   |   15.2 |    14.6 |     29.8 |
//! | backup 256 MiB                  |   15.1 |    14.8 |     29.9 |
//! | backup 1 GiB                    |   15.3 |    14.8 |     30.0 |
//! | backup 2 GiB                    |   15.3 |    15.2 |     30.4 |
//! | verify 64 MiB                   |    9.8 |     7.5 |     17.2 |
//! | verify 1 GiB                    |    9.8 |     7.6 |     17.4 |
//! | restore 64 MiB                  |   12.2 |    15.0 |     27.3 |
//! | restore 1 GiB                   |   12.3 |    15.1 |     27.4 |
//! | 3 targets x 256 MiB, `--jobs 1` |   15.6 |    15.3 |     30.8 |
//! | 3 targets x 256 MiB, `--jobs 3` |   26.0 |    44.7 |     70.7 |
//!
//! Between runs these figures move by +/-0.5 MiB. The tests' thresholds are set
//! well above that noise on purpose: what they have to detect is an
//! accumulation, not a fluctuation.
//!
//! What these figures say:
//!
//! - **The promise holds.** From 256 MiB to 2 GiB -- eight times more data --
//!   memory went from 29.9 to 30.4 MiB: 1.7 % more, noise. And from 64 MiB to
//!   1 GiB -- sixteen times more -- `backup`, `verify` and `restore` moved by
//!   1 %. A 2 GiB backup fits comfortably in a 512 MiB container: it uses 6 %.
//! - **The peak does not depend on the size because it does not appear during
//!   the flow.** It is reached at start-up -- tokio's runtime, zstd's and age's
//!   buffers, the channel's TLS -- and does not move from there: that is why
//!   sampled `VmRSS` and `VmHWM` agree to 0.0 % across the ten measurements.
//! - **`--jobs` costs about 20 MiB per simultaneous job** on top of a ~31 MiB
//!   baseline: three at once are 70.7 MiB, a 2.30x that stays below the 3x the
//!   parallelism would justify, because the core shares the runtime and only
//!   the plugin processes are duplicated. Sizing rule:
//!   `31 MiB + 20 MiB x jobs`, plus the storage target's ceiling (see above).

mod common;

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use common::{Bench, json_of};

use sb_crypto::Identity;

/// How often `/proc` is looked at. Finer adds nothing -- `VmHWM` does not miss
/// the peak -- and coarser would make the comparison between the two measures
/// useless.
const INTERVAL: Duration = Duration::from_millis(25);

/// A MiB in bytes: the unit the mock source is asked for a size in.
const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

/// A MiB in KiB: the unit `/proc` gives memory in, and therefore the unit of
/// every threshold in this file.
const MIB_IN_KIB: u64 = 1024;

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

/// The memory peak of a full run: the core and its plugins.
///
/// All figures in KiB, which is how `/proc/<pid>/status` gives them.
#[derive(Debug, Default, Clone, Copy)]
struct Peak {
    /// Maximum `VmRSS` of the core seen by the sampling.
    core_rss: u64,
    /// Maximum `VmHWM` of the core. It is the real peak.
    core_hwm: u64,
    /// Maximum **sum** of the plugins' `VmRSS` at a single instant.
    plugins_rss: u64,
    /// Sum of each seen plugin's `VmHWM`. An upper bound: if two plugins did
    /// not overlap in time, it adds two peaks that never happened at once.
    plugins_hwm: u64,
    /// The maximum of `core + plugins` **within the same sample**: what is
    /// really resident at once, and therefore what has to fit in the
    /// container's limit.
    simultaneous_rss: u64,
    /// How many distinct plugins were seen. It tells whether the sampling got
    /// to see them at all: zero plugins is an invalid measurement, not a
    /// success.
    plugins_seen: u64,
    samples: u64,
    duration: Duration,
}

impl Peak {
    /// Upper bound of what the whole system consumes.
    ///
    /// Adds the core's `VmHWM` and that of **each** plugin that was seen. When
    /// the plugins live at the same time -- a single target -- it is the exact
    /// figure. When they take turns -- several targets with `--jobs 1` -- it
    /// adds peaks that never coincided and comes out too high; that is what
    /// `simultaneous_rss` is for.
    fn total_hwm(self) -> u64 {
        self.core_hwm + self.plugins_hwm
    }
}

impl std::fmt::Display for Peak {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "core {} (sampled RSS {}) - plugins {} across {} processes (sampled RSS {}) \
             - resident at once {} - bound {} - {:.1} s, {} samples",
            mib(self.core_hwm),
            mib(self.core_rss),
            mib(self.plugins_hwm),
            self.plugins_seen,
            mib(self.plugins_rss),
            mib(self.simultaneous_rss),
            mib(self.total_hwm()),
            self.duration.as_secs_f64(),
            self.samples,
        )
    }
}

/// KiB to a text in MiB, which is the unit a container is thought of in.
fn mib(kib: u64) -> String {
    #[allow(clippy::cast_precision_loss)] // For printing, not for comparing.
    let m = kib as f64 / 1024.0;
    format!("{m:.1} MiB")
}

/// A process's `VmRSS` and `VmHWM`, in KiB.
///
/// `None` if the process is gone: when the child dies its `/proc/<pid>`
/// disappears, and that is the normal end of the sampling, not an error.
fn memory_of(pid: u32) -> Option<(u64, u64)> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let mut rss = None;
    let mut hwm = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            rss = kib_of(rest);
        } else if let Some(rest) = line.strip_prefix("VmHWM:") {
            hwm = kib_of(rest);
        }
    }
    Some((rss?, hwm?))
}

/// `       12345 kB` -> `12345`.
fn kib_of(rest: &str) -> Option<u64> {
    rest.split_whitespace().next()?.parse().ok()
}

/// A process's direct children, according to
/// `/proc/<pid>/task/<tid>/children`.
///
/// The threads have to be walked because each keeps its own list: the core is a
/// tokio runtime and does not always launch the plugin from the main thread.
fn children(pid: u32) -> Vec<u32> {
    let mut found = Vec::new();
    let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else {
        return found;
    };
    for task in tasks.flatten() {
        if let Ok(text) = std::fs::read_to_string(task.path().join("children")) {
            found.extend(
                text.split_whitespace()
                    .filter_map(|p| p.parse::<u32>().ok()),
            );
        }
    }
    found
}

/// All of `root`'s descendants. The plugins are direct children, but the whole
/// tree is walked in case one of them ever launches something.
fn descendants(root: u32) -> Vec<u32> {
    let mut seen = Vec::new();
    let mut pending = children(root);
    while let Some(pid) = pending.pop() {
        if seen.contains(&pid) {
            continue;
        }
        pending.extend(children(pid));
        seen.push(pid);
    }
    seen
}

/// The sampling loop. It exits as soon as `finished` is set, which is right
/// after the parent has reaped the child: reading `/proc` after that would be
/// measuring somebody else's pid.
fn sample(root: u32, finished: &AtomicBool) -> Peak {
    let start = Instant::now();
    let mut peak = Peak::default();
    let mut hwm_per_plugin: HashMap<u32, u64> = HashMap::new();

    while !finished.load(Ordering::Relaxed) {
        if let Some((rss, hwm)) = memory_of(root) {
            peak.core_rss = peak.core_rss.max(rss);
            peak.core_hwm = peak.core_hwm.max(hwm);
        }
        let mut rss_sum = 0;
        for plugin in descendants(root) {
            if let Some((rss, hwm)) = memory_of(plugin) {
                rss_sum += rss;
                let recorded = hwm_per_plugin.entry(plugin).or_default();
                *recorded = (*recorded).max(hwm);
            }
        }
        peak.plugins_rss = peak.plugins_rss.max(rss_sum);
        // The simultaneous total is computed **within** the sample: the core's
        // maximum and the plugins' maximum may not have happened at the same
        // time, and adding them separately would invent an instant that never
        // existed.
        let core_now = memory_of(root).map_or(0, |(rss, _)| rss);
        peak.simultaneous_rss = peak.simultaneous_rss.max(core_now + rss_sum);
        peak.samples += 1;
        std::thread::sleep(INTERVAL);
    }

    peak.plugins_hwm = hwm_per_plugin.values().sum();
    peak.plugins_seen = hwm_per_plugin.len() as u64;
    peak.duration = start.elapsed();
    peak
}

/// What a measured run left behind.
struct Run {
    peak: Peak,
    success: bool,
    stdout: String,
    stderr: String,
}

impl Run {
    /// Fails the test with the full output if the command did not go well. A
    /// memory test measuring a `shieldbk` that died at start-up would give a
    /// splendid figure and a lie.
    fn require(self, what: &str) -> Self {
        assert!(
            self.success,
            "{what} failed:\nstdout: {}\nstderr: {}",
            self.stdout, self.stderr
        );
        assert!(
            self.peak.core_hwm > 0,
            "{what}: the core's /proc was never read; the measurement is worthless"
        );
        assert!(
            self.peak.plugins_seen > 0,
            "{what}: no plugin process was seen; the measurement only covers the core and does \
             not prove what it is meant to"
        );
        self
    }
}

/// Runs `command` while measuring the memory peak of its whole process tree.
fn measure(command: &mut Command) -> Run {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();

    // The pipes are drained from separate threads: if they were allowed to fill
    // up, the child would block writing and the test would hang forever.
    let mut out = child.stdout.take().unwrap();
    let mut errors = child.stderr.take().unwrap();
    let stdout_reader = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = out.read_to_string(&mut text);
        text
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = errors.read_to_string(&mut text);
        text
    });

    let finished = Arc::new(AtomicBool::new(false));
    let sampler = {
        let finished = Arc::clone(&finished);
        std::thread::spawn(move || sample(pid, &finished))
    };

    // `wait` ends the wait and reaps the child: without this a zombie would be
    // left behind.
    let status = child.wait().unwrap();
    finished.store(true, Ordering::Relaxed);

    Run {
        peak: sampler.join().unwrap(),
        success: status.success(),
        stdout: stdout_reader.join().unwrap(),
        stderr: stderr_reader.join().unwrap(),
    }
}

// ---------------------------------------------------------------------------
// The test bench
// ---------------------------------------------------------------------------

/// An environment ready to measure: mock installed, registered and configured.
struct Scenario {
    bench: Bench,
    config: PathBuf,
    key: PathBuf,
}

impl Scenario {
    /// `targets` are pairs `(name, bytes the source emits)`.
    fn new(targets: &[(&str, u64)]) -> Self {
        let bench = Bench::new();
        bench.install_mock();

        let identity = Identity::generate();
        let key = bench.path("key.age");
        std::fs::write(
            &key,
            format!(
                "# created: 2026-08-21T00:00:00Z\n# public key: {}\n{}\n",
                identity.to_recipient(),
                identity.to_secret_string().expose()
            ),
        )
        .unwrap();

        let mut toml = format!(
            "[plugins]\ndir = {dir:?}\nlockfile = {lock:?}\n",
            dir = bench.plugins_dir().to_string_lossy(),
            lock = bench.lockfile().to_string_lossy(),
        );
        for (name, size) in targets {
            // Each target with its own directory: that way one's `restore.bin`
            // does not clobber another's and each one's disk can be inspected
            // separately.
            let data = bench.data_dir().join(name);
            std::fs::create_dir_all(&data).unwrap();
            write!(
                toml,
                "\n[[target]]\nname = \"{name}\"\nsource = \"mock\"\nstorage = \"mock\"\n\
                 recipient = \"{recipient}\"\n\
                 \n[target.source_config]\ndir = {data:?}\nseed = 7\nsize = {size}\n\
                 \n[target.storage_config]\ndir = {data:?}\n",
                recipient = identity.to_recipient(),
                data = data.to_string_lossy(),
            )
            .unwrap();
        }
        let config = bench.config(&toml);

        let lock = Command::new(env!("CARGO_BIN_EXE_shieldbk"))
            .env("HOME", bench.root.path())
            .env_remove("RUST_LOG")
            .args(["--config", &config.to_string_lossy(), "plugin", "lock"])
            .output()
            .unwrap();
        assert!(
            lock.status.success(),
            "plugin lock failed: {}",
            String::from_utf8_lossy(&lock.stderr)
        );

        Self { bench, config, key }
    }

    /// A `shieldbk` with the environment isolated and `--config` already set.
    fn command(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_shieldbk"));
        command
            .env("HOME", self.bench.root.path())
            .env_remove("RUST_LOG")
            .args(["--config", &self.config.to_string_lossy()])
            .args(arguments);
        command
    }

    /// A measured backup. It always runs in `--format json` so the artifact's
    /// key can be taken from the output and `verify` and `restore` chained.
    fn backup(&self, arguments: &[&str]) -> Run {
        let mut all = vec!["--format", "json"];
        all.extend_from_slice(arguments);
        measure(&mut self.command(&all)).require("backup")
    }

    /// The artifact key a backup in `--format json` left behind.
    fn key_of(run: &Run) -> String {
        json_of(run.stdout.as_bytes())["targets"][0]["artifact_key"]
            .as_str()
            .unwrap()
            .to_string()
    }

    /// Checks that the backup really moved the bytes it says it did.
    ///
    /// Without this, a memory test would pass with a broken configuration that
    /// backed nothing up: zero bytes also use constant memory. The mock's data
    /// is deliberately incompressible, so the encrypted artifact has to weigh
    /// practically the same as the dump.
    fn require_that_it_moved(&self, target: &str, key: &str, bytes: u64) {
        let path = self.bench.data_dir().join(target).join(key);
        let weight = std::fs::metadata(&path)
            .unwrap_or_else(|e| panic!("the artifact {} is not there: {e}", path.display()))
            .len();
        assert!(
            weight >= bytes / 10 * 9,
            "`{target}`'s artifact weighs {weight} B and {bytes} B were dumped: \
             the measurement did not cross the data it claims"
        );
    }

    /// Leaves the disk as it was: 2 GiB of artifacts per run pile up fast if
    /// they are not deleted between phases.
    fn clean(&self, target: &str) {
        let _ = std::fs::remove_dir_all(self.bench.data_dir().join(target));
        std::fs::create_dir_all(self.bench.data_dir().join(target)).unwrap();
    }
}

/// Checks that sampling and historical peak tell the same story.
///
/// If the sampling stays well below `VmHWM`, the peak happened between two
/// 25 ms readings. It is not a fault of the measured program, but it has to be
/// said, because it means the instantaneous figure being printed is not the one
/// that counts.
fn contrast(label: &str, peak: Peak) {
    #[allow(clippy::cast_precision_loss)]
    let deviation = if peak.core_hwm == 0 {
        0.0
    } else {
        1.0 - (peak.core_rss as f64 / peak.core_hwm as f64)
    };
    println!(
        "  [{label}] sampled VmRSS vs the core's VmHWM: {} vs {} ({:.1}% below)",
        mib(peak.core_rss),
        mib(peak.core_hwm),
        deviation * 100.0,
    );
}

/// The ratio between two peaks, to print it and to compare it.
#[allow(clippy::cast_precision_loss)]
fn ratio(large: u64, small: u64) -> f64 {
    if small == 0 {
        return f64::INFINITY;
    }
    large as f64 / small as f64
}

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------

#[test]
#[ignore = "moves gigabytes across the disk: cargo test --release --test memory -- --ignored --nocapture"]
fn memory_does_not_grow_with_the_size_of_the_backup() {
    // The test that decides whether the design is what it says it is. Eight
    // times more data through the same pipe: if the pipe does not accumulate,
    // the figure does not move.
    let scenario = Scenario::new(&[("small", 256 * MIB), ("large", 2 * GIB)]);

    let run = scenario.backup(&["backup", "small"]);
    let small = run.peak;
    scenario.require_that_it_moved("small", &Scenario::key_of(&run), 256 * MIB);
    println!("\n256 MiB -> {small}");
    contrast("256 MiB", small);
    scenario.clean("small");

    let run = scenario.backup(&["backup", "large"]);
    let large = run.peak;
    scenario.require_that_it_moved("large", &Scenario::key_of(&run), 2 * GIB);
    println!("  2 GiB -> {large}");
    contrast("2 GiB", large);
    scenario.clean("large");

    let growth = ratio(large.total_hwm(), small.total_hwm());
    println!(
        "\n  8x data -> {growth:.2}x memory ({} -> {})\n",
        mib(small.total_hwm()),
        mib(large.total_hwm()),
    );

    assert!(
        growth <= 1.5,
        "eight times more data cost {growth:.2}x the memory \
         ({} with 256 MiB, {} with 2 GiB). The constant-memory promise does not \
         hold: something accumulates in the pipeline.",
        mib(small.total_hwm()),
        mib(large.total_hwm()),
    );
}

#[test]
#[ignore = "moves gigabytes across the disk: cargo test --release --test memory -- --ignored --nocapture"]
fn a_large_backup_fits_in_a_reasonable_limit() {
    // The figure that makes a `--memory=512m` container believable.
    const LIMIT: u64 = 512 * MIB_IN_KIB;

    let scenario = Scenario::new(&[("large", 2 * GIB)]);
    let run = scenario.backup(&["backup", "large"]);
    let peak = run.peak;
    scenario.require_that_it_moved("large", &Scenario::key_of(&run), 2 * GIB);
    println!("\n2 GiB in a single backup -> {peak}\n");

    assert!(
        peak.core_hwm <= LIMIT,
        "the core reached {} backing up 2 GiB; the budget is {}",
        mib(peak.core_hwm),
        mib(LIMIT),
    );
    assert!(
        peak.total_hwm() <= LIMIT,
        "the whole system (core + plugins) reached {}; the budget is {}",
        mib(peak.total_hwm()),
        mib(LIMIT),
    );
}

#[test]
#[ignore = "moves gigabytes across the disk: cargo test --release --test memory -- --ignored --nocapture"]
fn the_full_cycle_does_not_accumulate_either() {
    // `backup` is the path that gets looked at most, but `verify` reads the
    // whole artifact and `restore` decrypts and decompresses it whole. If
    // either accumulated, the promise would hold for making copies and not for
    // using them, which is the only thing that justifies making them.
    const LIMIT: u64 = 512 * MIB_IN_KIB;

    // Two sizes per phase: with only one the consumption would be known, but
    // not whether it grows, which is the question.
    let scenario = Scenario::new(&[("tiny", 64 * MIB), ("big", GIB)]);

    let mut cycles = Vec::new();
    for (target, label) in [("tiny", "64 MiB"), ("big", "1 GiB")] {
        let run = scenario.backup(&["backup", target]);
        let backup = run.peak;
        let key = Scenario::key_of(&run);
        println!("\n[{label}] backup  -> {backup}");

        let verify = measure(&mut scenario.command(&["verify", target, &key]))
            .require("verify")
            .peak;
        println!("[{label}] verify  -> {verify}");

        let restore = measure(&mut scenario.command(&[
            "restore",
            target,
            &key,
            "--identity",
            &scenario.key.to_string_lossy(),
        ]))
        .require("restore")
        .peak;
        println!("[{label}] restore -> {restore}");
        contrast(label, restore);

        cycles.push([("backup", backup), ("verify", verify), ("restore", restore)]);
        scenario.clean(target);
    }
    let [tinies, bigs] = [cycles[0], cycles[1]];

    println!();
    for ((phase, tiny), (_, big)) in tinies.iter().zip(bigs.iter()) {
        println!(
            "  {phase:<8} 64 MiB -> 1 GiB (16x data): {} -> {} = {:.2}x",
            mib(tiny.total_hwm()),
            mib(big.total_hwm()),
            ratio(big.total_hwm(), tiny.total_hwm()),
        );
    }
    println!();

    for ((phase, tiny), (_, big)) in tinies.iter().zip(bigs.iter()) {
        let growth = ratio(big.total_hwm(), tiny.total_hwm());
        assert!(
            growth <= 1.5,
            "`{phase}` cost {growth:.2}x more memory with 16x more data \
             ({} -> {}): that phase accumulates.",
            mib(tiny.total_hwm()),
            mib(big.total_hwm()),
        );
        assert!(
            big.total_hwm() <= LIMIT,
            "`{phase}` with 1 GiB reached {}; the budget is {}",
            mib(big.total_hwm()),
            mib(LIMIT),
        );
    }
}

#[test]
#[ignore = "moves gigabytes across the disk: cargo test --release --test memory -- --ignored --nocapture"]
fn concurrency_multiplies_memory_predictably() {
    // Whoever sizes a container needs this and nothing else: how much raising
    // `--jobs` costs. That the cost be predictable matters more than that it be
    // low; what it cannot do is explode.
    const SIZE: u64 = 256 * MIB;
    const JOBS: u64 = 3;

    let scenario = Scenario::new(&[("one", SIZE), ("two", SIZE), ("three", SIZE)]);

    // With no target name all three are backed up, which is what gives `--jobs`
    // something to parallelise.
    let sequential = scenario.backup(&["--jobs", "1", "backup"]).peak;
    println!("\n3 targets x 256 MiB, --jobs 1 -> {sequential}");
    contrast("--jobs 1", sequential);
    for t in ["one", "two", "three"] {
        scenario.clean(t);
    }

    let parallel = scenario.backup(&["--jobs", "3", "backup"]).peak;
    println!("3 targets x 256 MiB, --jobs 3 -> {parallel}");
    contrast("--jobs 3", parallel);
    for t in ["one", "two", "three"] {
        scenario.clean(t);
    }

    // `total_hwm` is **not** valid here: with `--jobs 1` the six plugins take
    // turns, they are never alive at once, and adding their six historical
    // peaks would inflate the baseline being compared against -- making the
    // parallelism look free. The question is how much RAM is resident at the
    // same instant, and that is `simultaneous_rss`.
    let factor = ratio(parallel.simultaneous_rss, sequential.simultaneous_rss);
    let core_factor = ratio(parallel.core_hwm, sequential.core_hwm);
    let per_job = parallel
        .simultaneous_rss
        .saturating_sub(sequential.simultaneous_rss)
        / (JOBS - 1);
    println!(
        "\n  --jobs 1 -> --jobs 3: resident at once {} -> {} = {factor:.2}x \
         (the core's VmHWM {core_factor:.2}x)",
        mib(sequential.simultaneous_rss),
        mib(parallel.simultaneous_rss),
    );
    println!(
        "  For sizing: ~{} of baseline plus ~{} for each extra simultaneous job.\n",
        mib(sequential.simultaneous_rss),
        mib(per_job),
    );

    #[allow(clippy::cast_precision_loss)]
    let ceiling = JOBS as f64;
    assert!(
        factor <= ceiling,
        "with --jobs 3 the resident memory was multiplied by {factor:.2} \
         ({} -> {}), more than the parallelism justifies (x{ceiling:.0}). The \
         cost of `--jobs` is not proportional: something accumulates per job.",
        mib(sequential.simultaneous_rss),
        mib(parallel.simultaneous_rss),
    );
    // And in case the parallelism amounted to nothing: with three at once there
    // has to be more resident than with one, or the test is not measuring
    // `--jobs`.
    assert!(
        factor > 1.0,
        "with --jobs 3 the resident memory did not rise compared to --jobs 1 \
         ({} -> {}): either there was no real parallelism or the sampling did not see it",
        mib(sequential.simultaneous_rss),
        mib(parallel.simultaneous_rss),
    );
}
