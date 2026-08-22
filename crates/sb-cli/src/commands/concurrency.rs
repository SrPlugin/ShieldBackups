//! How many targets are touched at a time.
//!
//! `--jobs` is not a performance option: it is a brake. A backup fires a dump
//! at a server that is also serving users, and three targets in parallel are
//! three dumps competing for the same disk and the same cache. That is why the
//! default value is one and why the limit is always applied, even when somebody
//! asks for more jobs than there are targets.
//!
//! The other reason this lives apart is that the policy has to be the same in
//! `backup` and in `doctor`: if each built its own loop, raising the brake in
//! one and forgetting it in the other would be a matter of time.

use std::sync::Arc;

use tokio::sync::Semaphore;

/// Runs `task` over each item with at most `jobs` at a time.
///
/// The results come out **in input order**, not in completion order: a report
/// whose order depended on which database was fastest today would be impossible
/// to compare with yesterday's.
///
/// No item aborts the others. It is the same reason as in `doctor`: whoever
/// backs up ten targets wants to know which ones failed, not which one failed
/// first.
pub async fn in_batches<T, R, F, Fut>(items: Vec<T>, jobs: usize, task: F) -> Vec<R>
where
    F: Fn(T) -> Fut,
    Fut: Future<Output = R>,
{
    // Zero permits would leave the process waiting for one that never comes.
    // Whoever writes `--jobs 0` meant "few", not "none".
    let permits = Arc::new(Semaphore::new(jobs.max(1)));

    let pending = items.into_iter().map(|item| {
        let permits = Arc::clone(&permits);
        let future = task(item);
        async move {
            // The permit is asked for **before** the task advances a single
            // step, and is released on finishing because the guard dies here.
            // `acquire_owned` only fails if the semaphore is closed, and this
            // one lives exactly as long as this loop.
            let _permit = permits.acquire_owned().await;
            future.await
        }
    });

    futures_util::future::join_all(pending).await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[tokio::test]
    async fn the_results_come_out_in_input_order() {
        // Even though the work finishes out of order: a report whose order
        // depends on which target was fastest today cannot be compared with
        // yesterday's.
        let out = in_batches(vec![3_u64, 1, 2], 3, |n| async move {
            tokio::time::sleep(std::time::Duration::from_millis(n * 20)).await;
            n
        })
        .await;
        assert_eq!(out, vec![3, 1, 2]);
    }

    #[tokio::test]
    async fn there_are_never_more_than_jobs_at_a_time() {
        // It is the module's reason to exist: two simultaneous dumps against
        // the same server is exactly what has to be avoided.
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        in_batches((0..8).collect(), 2, |_| {
            let live = Arc::clone(&live);
            let peak = Arc::clone(&peak);
            async move {
                let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                live.fetch_sub(1, Ordering::SeqCst);
            }
        })
        .await;

        let top = peak.load(Ordering::SeqCst);
        assert!(top <= 2, "{top} ran at once with --jobs 2");
        assert!(
            top >= 2,
            "with --jobs 2 and eight tasks there should be parallelism"
        );
    }

    #[tokio::test]
    async fn jobs_zero_is_treated_as_one() {
        let out = in_batches(vec![1, 2], 0, |n| async move { n * 2 }).await;
        assert_eq!(out, vec![2, 4]);
    }

    #[tokio::test]
    async fn with_a_single_job_the_tasks_do_not_overlap() {
        // The default value, and the one that really protects the server.
        let live = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        in_batches((0..4).collect(), 1, |_| {
            let live = Arc::clone(&live);
            let peak = Arc::clone(&peak);
            async move {
                let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                live.fetch_sub(1, Ordering::SeqCst);
            }
        })
        .await;

        assert_eq!(peak.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_empty_list_does_nothing() {
        let out: Vec<u8> = in_batches(Vec::new(), 4, |n: u8| async move { n }).await;
        assert!(out.is_empty());
    }
}
