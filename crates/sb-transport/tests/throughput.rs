// As in the rest of the workspace's tests: here an `unwrap` is what is wanted,
// so that the test blows up exactly where it failed. These helpers are free
// functions of a `tests/` file, so the `clippy.toml` allowance -- which only
// reaches `#[test]` and `#[cfg(test)]` -- does not get to them and has to be
// granted at file level.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! How fast is the data channel, really?
//!
//! The data channel is the one piece of the system deliberately built without
//! TLS and without framing: both ends are processes of the same user on the
//! same machine, and everything put on that path is paid for once per byte of
//! every backup. `crates/sb-transport/src/data.rs` justifies that decision by
//! saying the socket is fast enough that adding anything to it would be
//! visible. This file is the measurement behind that claim, so it is not
//! something the documentation merely asserts.
//!
//! # What is measured
//!
//! 256 MiB through a real [`DataChannel`] -- the same `create`/`accept`/
//! `connect_data` a backup uses, not a raw `UnixStream` pair. One task writes,
//! another reads, and the clock covers only the transfer: the integrity check
//! runs afterwards, with the clock stopped, so that comparing the bytes does
//! not get charged to the channel.
//!
//! Integrity is checked because a very fast channel that corrupts data is worth
//! nothing. Each 1 MiB chunk carries its index in its first eight bytes and a
//! `0..=255` ramp in the rest, so a reordering, a repetition or a lost chunk
//! shows up and not only a flipped bit.
//!
//! # What is asserted
//!
//! A floor of 500 MB/s, far below what the channel does. The exact figure
//! depends on the machine -- cores, kernel, socket buffers, how loaded the
//! runner is -- and asserting it would be asserting the hardware. What this
//! floor catches is an order-of-magnitude regression, which is the one that
//! would matter: it would mean somebody put framing, an extra copy or a
//! chunk-sized allocation on the hot path.
//!
//! # How it is run
//!
//! ```text
//! cargo test -p sb-transport --release --test throughput -- --ignored --nocapture
//! ```
//!
//! `#[ignore]`d, like the memory tests in `crates/sb-cli/tests/memory.rs`: it
//! moves a quarter of a gigabyte and there is no reason to pay for that on
//! every push. **In release**: in debug the read loop and the pattern check are
//! not optimised and the figure measures the profile, not the channel.
//! `--nocapture` is what makes the number visible; without it the test says
//! "ok" and shows nothing, which is the opposite of the point.

use std::time::{Duration, Instant};

use sb_transport::{DataChannel, connect_data};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// Size of each write. A backup's real writes are of this order, and it is big
/// enough that the syscall does not dominate the measurement.
const CHUNK: usize = 1024 * 1024;

/// How many chunks are moved: 256 MiB. Enough for the transfer to last long
/// enough to be timed without the test costing seconds.
const CHUNKS: usize = 256;

const TOTAL: usize = CHUNK * CHUNKS;

/// The floor the throughput has to clear, in bytes per second.
///
/// Decimal MB, which is the unit the figure is reported in.
const FLOOR: f64 = 500e6;

/// The content of chunk number `index`.
///
/// The first eight bytes are the index and the rest is a `0..=255` ramp. The
/// index is what turns the check into something more than a checksum: two
/// chunks swapped, one repeated or one missing all change it, and a plain
/// repeating pattern would hide every one of those.
fn chunk(index: usize) -> Vec<u8> {
    let mut buffer = vec![0_u8; CHUNK];
    fill(&mut buffer, index);
    buffer
}

/// Writes chunk `index`'s content into `buffer`, which reuses the allocation
/// across chunks.
fn fill(buffer: &mut [u8], index: usize) {
    for (i, byte) in buffer.iter_mut().enumerate() {
        #[allow(clippy::cast_possible_truncation)] // The ramp is the low byte.
        {
            *byte = i as u8;
        }
    }
    buffer[..8].copy_from_slice(&(index as u64).to_le_bytes());
}

/// Bytes per second, for printing and for comparing.
#[allow(clippy::cast_precision_loss)] // Figures for reporting, not for exact arithmetic.
fn rate(bytes: usize, elapsed: Duration) -> f64 {
    bytes as f64 / elapsed.as_secs_f64()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "moves 256 MiB: cargo test -p sb-transport --release --test throughput -- --ignored --nocapture"]
async fn the_data_channel_moves_bytes_at_the_speed_of_the_socket() {
    let dir = tempfile::tempdir().unwrap();
    let channel = DataChannel::create(dir.path(), "throughput").unwrap();
    let path = channel.path().to_path_buf();

    // The plugin's side of a dump: it produces and writes until it runs out.
    let writer = tokio::spawn(async move {
        let mut stream = connect_data(&path).await.unwrap();
        let mut buffer = vec![0_u8; CHUNK];
        for index in 0..CHUNKS {
            fill(&mut buffer, index);
            stream.write_all(&buffer).await.unwrap();
        }
        stream.shutdown().await.unwrap();
    });

    let mut stream = channel.accept().await.unwrap();

    // The clock starts after the `accept`, so that setting the channel up and
    // spawning the task are not charged to the transfer. Whatever the writer
    // managed to put in the socket buffer before this point is at most a few
    // hundred KiB against 256 MiB: below the noise.
    let mut received = vec![0_u8; TOTAL];
    let start = Instant::now();
    stream.read_exact(&mut received).await.unwrap();
    let elapsed = start.elapsed();

    // Clock stopped: from here on nothing costs the channel anything.
    let throughput = rate(TOTAL, elapsed);
    println!(
        "\n  {} MiB through a DataChannel in {:.3} s -> {:.2} GB/s ({:.0} MB/s, {:.0} MiB/s)\n",
        TOTAL / 1024 / 1024,
        elapsed.as_secs_f64(),
        throughput / 1e9,
        throughput / 1e6,
        throughput / 1024.0 / 1024.0,
    );

    // The end of the stream has to arrive, and nothing may come after the
    // 256 MiB: a channel that sends more than it was given is as broken as one
    // that sends less.
    let mut extra = [0_u8; 64];
    assert_eq!(
        stream.read(&mut extra).await.unwrap(),
        0,
        "the stream did not end after {TOTAL} B: the channel delivered more than was written"
    );
    writer.await.unwrap();

    // A very fast channel that corrupts data is worth nothing. Chunk by chunk,
    // comparing whole slices so that the check is a `memcmp` and not a loop
    // over 256 million bytes.
    for index in 0..CHUNKS {
        let expected = chunk(index);
        let got = &received[index * CHUNK..(index + 1) * CHUNK];
        assert_eq!(
            got.len(),
            expected.len(),
            "chunk {index} came back the wrong length"
        );
        assert!(
            got == expected.as_slice(),
            "chunk {index} came back altered: the channel corrupts, reorders or repeats data. \
             Its first eight bytes are {:?} and {:?} was expected",
            &got[..8],
            &expected[..8],
        );
    }

    assert!(
        throughput >= FLOOR,
        "the data channel moved {:.0} MB/s, below the {:.0} MB/s floor. \
         The figure depends on the machine, so a small drop means nothing; \
         one this size means something was put on the hot path -- framing, an \
         extra copy, an allocation per chunk -- or the socket stopped being a \
         plain `UnixStream`.",
        throughput / 1e6,
        FLOOR / 1e6,
    );
}
