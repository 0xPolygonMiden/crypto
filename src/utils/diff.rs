/// A trait for computing the difference between two objects.
pub trait Diff<K: Ord + Clone, V: Clone> {
    type DiffType;

    /// Returns a `Self::DiffType` object that represents the difference between this object and
    /// other.
    fn diff(&self, other: &Self) -> Self::DiffType;
}

/// A trait for applying the difference between two objects.
pub trait ApplyDiff<K: Ord + Clone, V: Clone> {
    type DiffType;

    /// Applies the provided changes described by [DiffType] to the object implementing this trait.
    fn apply(&mut self, diff: Self::DiffType);
}
