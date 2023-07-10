/// A trait for computing the difference between two objects.
pub trait Diff<K: Ord + Clone, V: Clone> {
    /// The type that describes the difference between two objects.
    type DiffType;

    /// Returns a [Self::DiffType] object that represents the difference between this object and
    /// other.
    fn diff(&self, other: &Self) -> Self::DiffType;
}

/// A trait for applying the difference between two objects.
pub trait ApplyDiff<K: Ord + Clone, V: Clone> {
    /// The type that describes the difference between two objects.
    type DiffType;

    /// Applies the provided changes described by [Self::DiffType] to the object implementing this trait.
    fn apply(&mut self, diff: Self::DiffType);
}

/// A trait for applying the difference between two objects with the possibility of failure.
pub trait TryApplyDiff<K: Ord + Clone, V: Clone> {
    /// The type that describes the difference between two objects.
    type DiffType;

    /// An error type that can be returned if the changes cannot be applied.
    type Error;

    /// Applies the provided changes described by [Self::DiffType] to the object implementing this trait.
    /// Returns an error if the changes cannot be applied.
    fn try_apply(&mut self, diff: Self::DiffType) -> Result<(), Self::Error>;
}
