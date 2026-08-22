//! Splitting a stream into parts of uniform size.
//!
//! It lives apart from the upload because it is the piece that decides whether
//! R2 accepts or rejects the whole multipart, and because that way it can be
//! tested without networking: the tests below are the contract.

use tokio::io::{AsyncRead, AsyncReadExt as _};

/// Splits a stream into parts of exactly `size` bytes, except the last one.
///
/// **R2 requires every part except the last to be the same size**, unlike S3,
/// which tolerates otherwise. That is why each part is filled up to completion
/// instead of emitting whatever a single read returned: a socket delivers bytes
/// in arbitrary chunks, and trusting them would produce uneven parts that R2
/// rejects. The failure, moreover, would only show up with large files and in
/// production.
pub struct Chunker<R> {
    source: R,
    size: usize,
    /// The source already returned a zero: there are no bytes left to read.
    exhausted: bool,
    /// Parts already emitted. It tells the empty stream -- which does produce
    /// one part, an empty one -- from the stream that ended exactly on a
    /// multiple of the size, which must not produce an extra empty part.
    emitted: u64,
    total: u64,
}

impl<R: AsyncRead + Unpin> Chunker<R> {
    /// A chunker over `source` that emits parts of `size` bytes.
    ///
    /// A size of zero is raised to one: there is no chunking possible with
    /// empty parts, and the alternative would be an infinite loop. The
    /// configuration already prevents getting here with less than 5 MiB.
    pub fn new(source: R, size: usize) -> Self {
        Self {
            source,
            size: size.max(1),
            exhausted: false,
            emitted: 0,
            total: 0,
        }
    }

    /// Returns the next part, or `None` when finished.
    ///
    /// Every part is `size` long except the last, which may be smaller. An
    /// empty stream produces a single empty part.
    ///
    /// # Errors
    ///
    /// The source's read error, as is: the caller knows what that source is and
    /// can say where it came from.
    pub async fn next_chunk(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        if self.exhausted && self.emitted > 0 {
            return Ok(None);
        }
        let mut part = vec![0_u8; self.size];
        let mut filled = 0;
        // The loop is the key: a single read returns whatever reached the
        // socket, which is almost never a whole part. It keeps insisting until
        // the part is complete or the source runs out.
        while filled < self.size {
            let read = self.source.read(&mut part[filled..]).await?;
            if read == 0 {
                self.exhausted = true;
                break;
            }
            filled += read;
        }
        // The last part comes up short; the rest do not.
        part.truncate(filled);
        self.total += as_u64(filled);

        // A stream whose size is an exact multiple of the part runs out here
        // with zero bytes read: that is not a part, it is the end.
        if filled == 0 && self.emitted > 0 {
            return Ok(None);
        }
        self.emitted += 1;
        Ok(Some(part))
    }

    /// Bytes read from the source so far.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.total
    }
}

/// `usize` to `u64` without an `as` that clippy would have to forgive. On the
/// platforms the project supports the conversion never saturates.
fn as_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A source that delivers bytes one at a time: the worst possible case, and
    /// the one that reveals whether the chunking depends on how the data
    /// arrived.
    struct Trickle(Vec<u8>, usize);
    impl tokio::io::AsyncRead for Trickle {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.1 >= self.0.len() {
                return std::task::Poll::Ready(Ok(()));
            }
            let b = self.0[self.1];
            self.1 += 1;
            buf.put_slice(&[b]);
            std::task::Poll::Ready(Ok(()))
        }
    }

    async fn chunk_all<R: tokio::io::AsyncRead + Unpin>(r: R, size: usize) -> Vec<Vec<u8>> {
        let mut c = Chunker::new(r, size);
        let mut parts = Vec::new();
        while let Some(p) = c.next_chunk().await.unwrap() {
            parts.push(p);
        }
        parts
    }

    #[tokio::test]
    async fn it_chunks_into_parts_of_the_same_size_except_the_last() {
        // R2's rule: all equal except the last one.
        let parts = chunk_all(&vec![1_u8; 25][..], 10).await;
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].len(), 10);
        assert_eq!(parts[1].len(), 10);
        assert_eq!(parts[2].len(), 5);
    }

    #[tokio::test]
    async fn an_exact_stream_does_not_produce_an_empty_part() {
        let parts = chunk_all(&vec![1_u8; 20][..], 10).await;
        assert_eq!(
            parts.len(),
            2,
            "20 bytes in parts of 10 are two parts, not three"
        );
    }

    #[tokio::test]
    async fn a_stream_shorter_than_a_part_produces_just_one() {
        let parts = chunk_all(&vec![1_u8; 3][..], 10).await;
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].len(), 3);
    }

    #[tokio::test]
    async fn an_empty_stream_produces_an_empty_part() {
        // A zero-byte artifact does not exist (age always emits a header), but
        // the chunker must not break if it happens.
        let parts = chunk_all(&b""[..], 10).await;
        assert_eq!(parts.len(), 1);
        assert!(parts[0].is_empty());
    }

    #[tokio::test]
    async fn the_content_is_preserved_when_chunking() {
        let data: Vec<u8> = (0..100_u32).map(|i| (i % 251) as u8).collect();
        let parts = chunk_all(&data[..], 7).await;
        let rebuilt: Vec<u8> = parts.into_iter().flatten().collect();
        assert_eq!(rebuilt, data);
    }

    #[tokio::test]
    async fn one_byte_reads_do_not_alter_the_chunking() {
        // A socket delivers bytes in arbitrary chunks. If the chunking depended
        // on that, R2 would reject the parts for uneven size.
        let parts = chunk_all(Trickle(vec![7_u8; 25], 0), 10).await;
        assert_eq!(
            parts.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![10, 10, 5]
        );
    }

    #[tokio::test]
    async fn chunking_a_slow_socket_preserves_the_content() {
        let data: Vec<u8> = (0..1000_u32).map(|i| (i % 251) as u8).collect();
        let parts = chunk_all(Trickle(data.clone(), 0), 64).await;
        assert_eq!(parts.iter().flatten().copied().collect::<Vec<u8>>(), data);
        let (last, rest) = parts.split_last().unwrap();
        assert!(
            rest.iter().all(|p| p.len() == 64),
            "the intermediate ones, all equal"
        );
        assert!(last.len() <= 64);
    }

    #[tokio::test]
    async fn a_read_error_is_propagated() {
        struct Broken;
        impl tokio::io::AsyncRead for Broken {
            fn poll_read(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                _: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Ready(Err(std::io::Error::other("broken")))
            }
        }
        let mut c = Chunker::new(Broken, 10);
        assert!(c.next_chunk().await.is_err());
    }

    #[tokio::test]
    async fn it_counts_the_total_bytes() {
        // The vector is bound to a name because the chunker borrows it and it
        // has to outlive the `let`.
        let data = [1_u8; 25];
        let mut c = Chunker::new(&data[..], 10);
        while c.next_chunk().await.unwrap().is_some() {}
        assert_eq!(c.total(), 25);
    }
}
