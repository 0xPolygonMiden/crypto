use super::super::{RpoDigest, Vec};

/// Container for the update data of a [PartialMmr]
#[derive(Debug)]
pub struct MmrDelta {
    /// The new version of the [Mmr]
    pub forest: usize,

    /// Update data.
    ///
    /// The data is packed as follows:
    /// 1. All the elements needed to perform authentication path updates. These are the right
    ///    siblings required to perform tree merges on the [PartialMmr].
    /// 2. The new peaks.
    pub data: Vec<RpoDigest>,
}
