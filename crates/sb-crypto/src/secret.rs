use zeroize::Zeroize;

/// Container for a sensitive value.
///
/// It deliberately implements neither `Debug` nor `Display`: if something tries
/// to print a secret, the result must be a compile error, not a log line. The
/// contents are wiped from memory when the value is dropped.
///
/// # What it guarantees and what it does not
///
/// It guarantees that a credential cannot end up in a log by accident, and that
/// the value this container owns is wiped on drop.
///
/// It does **not** guarantee that no copy survives in memory. A `String` that
/// reallocates as it grows leaves its previous buffer behind unwiped, and
/// cloning a `Secret` creates a new, independent allocation. Build the value at
/// its final capacity whenever you can, and do not assume more protection than
/// is actually here.
///
/// `PartialEq` comparison is constant-time over the contents, but returns early
/// when the lengths differ: it leaks the length, not the value. That is the
/// standard behaviour for comparing credentials.
#[derive(Clone)]
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// The only way to reach the value. The name is deliberately awkward so
    /// that every use stands out in code review.
    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize + AsRef<[u8]>> PartialEq for Secret<T> {
    fn eq(&self, other: &Self) -> bool {
        let a = self.0.as_ref();
        let b = other.0.as_ref();
        if a.len() != b.len() {
            return false;
        }
        // Comparison without an early exit: it does not leak through timing how
        // much of the prefix matched.
        a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }
}

impl<T: Zeroize + AsRef<[u8]>> Eq for Secret<T> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_the_value_only_when_explicitly_asked() {
        let s = Secret::new(String::from("hunter2"));
        assert_eq!(s.expose(), "hunter2");
    }

    #[test]
    fn two_secrets_with_the_same_value_are_equal() {
        let a = Secret::new(String::from("same"));
        let b = Secret::new(String::from("same"));
        // `assert!` rather than `assert_eq!`: the latter would require `Debug`,
        // which `Secret` deliberately does not implement.
        assert!(a == b);
    }

    #[test]
    fn comparison_is_constant_time_for_bytes() {
        // This does not measure time: it checks that the comparison path exists
        // and is correct.
        let a = Secret::new(vec![1_u8, 2, 3]);
        let b = Secret::new(vec![1_u8, 2, 3]);
        let c = Secret::new(vec![1_u8, 2, 4]);
        assert!(a == b);
        assert!(a != c);
    }

    #[test]
    fn can_be_cloned() {
        let a = Secret::new(String::from("x"));
        let b = a.clone();
        assert_eq!(b.expose(), "x");
    }
}
