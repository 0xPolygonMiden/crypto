use crate::{
    hash::rpo::{Rpo256, RpoDigest},
    merkle::{
        mmr::{leaf_to_corresponding_tree, nodes_in_forest},
        InOrderIndex, MerklePath, MmrError, MmrPeaks,
    },
    utils::collections::{BTreeMap, Vec},
};

use super::{MmrDelta, MmrProof};

/// Partially materialized [Mmr], used to efficiently store and update the authentication paths for
/// a subset of the elements in a full [Mmr].
///
/// This structure store only the authentication path for a value, the value itself is stored
/// separately.
#[derive(Debug)]
pub struct PartialMmr {
    /// The version of the [Mmr].
    ///
    /// This value serves the following purposes:
    ///
    /// - The forest is a counter for the total number of elements in the [Mmr].
    /// - Since the [Mmr] is an append-only structure, every change to it causes a change to the
    ///   `forest`, so this value has a dual purpose as a version tag.
    /// - The bits in the forest also corresponds to the count and size of every perfect binary
    ///   tree that composes the [Mmr] structure, which server to compute indexes and perform
    ///   validation.
    pub(crate) forest: usize,

    /// The [Mmr] peaks.
    ///
    /// The peaks are used for two reasons:
    ///
    /// 1. It authenticates the addition of an element to the [PartialMmr], ensuring only valid
    ///    elements are tracked.
    /// 2. During a [Mmr] update peaks can be merged by hashing the left and right hand sides. The
    ///    peaks are used as the left hand.
    ///
    /// All the peaks of every tree in the [Mmr] forest. The peaks are always ordered by number of
    /// leaves, starting from the peak with most children, to the one with least.
    pub(crate) peaks: Vec<RpoDigest>,

    /// Authentication nodes used to construct merkle paths for a subset of the [Mmr]'s leaves.
    ///
    /// This does not include the [Mmr]'s peaks nor the tracked nodes, only the elements required
    /// to construct their authentication paths. This property is used to detect when elements can
    /// be safely removed from, because they are no longer required to authenticate any element in
    /// the [PartialMmr].
    ///
    /// The elements in the [Mmr] are referenced using a in-order tree index. This indexing scheme
    /// permits for easy computation of the relative nodes (left/right children, sibling, parent),
    /// which is useful for traversal. The indexing is also stable, meaning that merges to the
    /// trees in the [Mmr] can be represented without rewrites of the indexes.
    pub(crate) nodes: BTreeMap<InOrderIndex, RpoDigest>,

    /// Flag indicating if the odd element should be tracked.
    ///
    /// This flag is necessary because the sibling of the odd doesn't exist yet, so it can not be
    /// added into `nodes` to signal the value is being tracked.
    pub(crate) track_latest: bool,
}

impl PartialMmr {
    // CONSTRUCTORS
    // --------------------------------------------------------------------------------------------

    /// Constructs a [PartialMmr] from the given [MmrPeaks].
    pub fn from_peaks(accumulator: MmrPeaks) -> Self {
        let forest = accumulator.num_leaves();
        let peaks = accumulator.peaks().to_vec();
        let nodes = BTreeMap::new();
        let track_latest = false;

        Self { forest, peaks, nodes, track_latest }
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    // Gets the current `forest`.
    //
    // This value corresponds to the version of the [PartialMmr] and the number of leaves in it.
    pub fn forest(&self) -> usize {
        self.forest
    }

    // Returns a reference to the current peaks in the [PartialMmr]
    pub fn peaks(&self) -> &[RpoDigest] {
        &self.peaks
    }

    /// Given a leaf position, returns the Merkle path to its corresponding peak. If the position
    /// is greater-or-equal than the tree size an error is returned. If the requested value is not
    /// tracked returns `None`.
    ///
    /// Note: The leaf position is the 0-indexed number corresponding to the order the leaves were
    /// added, this corresponds to the MMR size _prior_ to adding the element. So the 1st element
    /// has position 0, the second position 1, and so on.
    pub fn open(&self, pos: usize) -> Result<Option<MmrProof>, MmrError> {
        let tree_bit =
            leaf_to_corresponding_tree(pos, self.forest).ok_or(MmrError::InvalidPosition(pos))?;
        let depth = tree_bit as usize;

        let mut nodes = Vec::with_capacity(depth);
        let mut idx = InOrderIndex::from_leaf_pos(pos);

        while let Some(node) = self.nodes.get(&idx.sibling()) {
            nodes.push(*node);
            idx = idx.parent();
        }

        // If there are nodes then the path must be complete, otherwise it is a bug
        debug_assert!(nodes.is_empty() || nodes.len() == depth);

        if nodes.len() != depth {
            // The requested `pos` is not being tracked.
            Ok(None)
        } else {
            Ok(Some(MmrProof {
                forest: self.forest,
                position: pos,
                merkle_path: MerklePath::new(nodes),
            }))
        }
    }

    // MODIFIERS
    // --------------------------------------------------------------------------------------------

    /// Add the authentication path represented by [MerklePath] if it is valid.
    ///
    /// The `index` refers to the global position of the leaf in the [Mmr], these are 0-indexed
    /// values assigned in a strictly monotonic fashion as elements are inserted into the [Mmr],
    /// this value corresponds to the values used in the [Mmr] structure.
    ///
    /// The `node` corresponds to the value at `index`, and `path` is the authentication path for
    /// that element up to its corresponding Mmr peak. The `node` is only used to compute the root
    /// from the authentication path to valid the data, only the authentication data is saved in
    /// the structure. If the value is required it should be stored out-of-band.
    pub fn add(
        &mut self,
        index: usize,
        node: RpoDigest,
        path: &MerklePath,
    ) -> Result<(), MmrError> {
        // Checks there is a tree with same depth as the authentication path, if not the path is
        // invalid.
        let tree = 1 << path.depth();
        if tree & self.forest == 0 {
            return Err(MmrError::UnknownPeak);
        };

        if index + 1 == self.forest
            && path.depth() == 0
            && self.peaks.last().map_or(false, |v| *v == node)
        {
            self.track_latest = true;
            return Ok(());
        }

        // ignore the trees smaller than the target (these elements are position after the current
        // target and don't affect the target index)
        let target_forest = self.forest ^ (self.forest & (tree - 1));
        let peak_pos = (target_forest.count_ones() - 1) as usize;

        // translate from mmr index to merkle path
        let path_idx = index - (target_forest ^ tree);

        // Compute the root of the authentication path, and check it matches the current version of
        // the PartialMmr.
        let computed = path.compute_root(path_idx as u64, node).map_err(MmrError::MerkleError)?;
        if self.peaks[peak_pos] != computed {
            return Err(MmrError::InvalidPeak);
        }

        let mut idx = InOrderIndex::from_leaf_pos(index);
        for node in path.nodes() {
            self.nodes.insert(idx.sibling(), *node);
            idx = idx.parent();
        }

        Ok(())
    }

    /// Remove a leaf of the [PartialMmr] and the unused nodes from the authentication path.
    ///
    /// Note: `leaf_pos` corresponds to the position the [Mmr] and not on an individual tree.
    pub fn remove(&mut self, leaf_pos: usize) {
        let mut idx = InOrderIndex::from_leaf_pos(leaf_pos);

        self.nodes.remove(&idx.sibling());

        // `idx` represent the element that can be computed by the authentication path, because
        // these elements can be computed they are not saved for the authentication of the current
        // target. In other words, if the idx is present it was added for the authentication of
        // another element, and no more elements should be removed otherwise it would remove that
        // element's authentication data.
        while !self.nodes.contains_key(&idx) {
            idx = idx.parent();
            self.nodes.remove(&idx.sibling());
        }
    }

    /// Applies updates to the [PartialMmr].
    pub fn apply(&mut self, delta: MmrDelta) -> Result<(), MmrError> {
        if delta.forest < self.forest {
            return Err(MmrError::InvalidPeaks);
        }

        if delta.forest == self.forest {
            if !delta.data.is_empty() {
                return Err(MmrError::InvalidUpdate);
            }

            return Ok(());
        }

        // find the tree merges
        let changes = self.forest ^ delta.forest;
        let largest = 1 << changes.ilog2();
        let merges = self.forest & (largest - 1);

        debug_assert!(
            !self.track_latest || (merges & 1) == 1,
            "if there is an odd element, a merge is required"
        );

        // count the number elements needed to produce largest from the current state
        let (merge_count, new_peaks) = if merges != 0 {
            let depth = largest.trailing_zeros();
            let skipped = merges.trailing_zeros();
            let computed = merges.count_ones() - 1;
            let merge_count = depth - skipped - computed;

            let new_peaks = delta.forest & (largest - 1);

            (merge_count, new_peaks)
        } else {
            (0, changes)
        };

        // verify the delta size
        if (delta.data.len() as u32) != merge_count + new_peaks.count_ones() {
            return Err(MmrError::InvalidUpdate);
        }

        // keeps track of how many data elements from the update have been consumed
        let mut update_count = 0;

        if merges != 0 {
            // starts at the smallest peak and follows the merged peaks
            let mut peak_idx = forest_to_root_index(self.forest);

            // match order of the update data while applying it
            self.peaks.reverse();

            // set to true when the data is needed for authentication paths updates
            let mut track = self.track_latest;
            self.track_latest = false;

            let mut peak_count = 0;
            let mut target = 1 << merges.trailing_zeros();
            let mut new = delta.data[0];
            update_count += 1;

            while target < largest {
                // check if either the left or right subtrees have saved for authentication paths.
                // If so, turn tracking on to update those paths.
                if target != 1 && !track {
                    let left_child = peak_idx.left_child();
                    let right_child = peak_idx.right_child();
                    track = self.nodes.contains_key(&left_child)
                        | self.nodes.contains_key(&right_child);
                }

                // update data only contains the nodes from the right subtrees, left nodes are
                // either previously known peaks or computed values
                let (left, right) = if target & merges != 0 {
                    let peak = self.peaks[peak_count];
                    peak_count += 1;
                    (peak, new)
                } else {
                    let update = delta.data[update_count];
                    update_count += 1;
                    (new, update)
                };

                if track {
                    self.nodes.insert(peak_idx.sibling(), right);
                }

                peak_idx = peak_idx.parent();
                new = Rpo256::merge(&[left, right]);
                target <<= 1;
            }

            debug_assert!(peak_count == (merges.count_ones() as usize));

            // restore the peaks order
            self.peaks.reverse();
            // remove the merged peaks
            self.peaks.truncate(self.peaks.len() - peak_count);
            // add the newly computed peak, the result of the merges
            self.peaks.push(new);
        }

        // The rest of the update data is composed of peaks. None of these elements can contain
        // tracked elements because the peaks were unknown, and it is not possible to add elements
        // for tacking without authenticating it to a peak.
        self.peaks.extend_from_slice(&delta.data[update_count..]);
        self.forest = delta.forest;

        debug_assert!(self.peaks.len() == (self.forest.count_ones() as usize));

        Ok(())
    }
}

// CONVERSIONS
// ================================================================================================

impl From<MmrPeaks> for PartialMmr {
    fn from(peaks: MmrPeaks) -> Self {
        Self::from_peaks(peaks)
    }
}

impl From<PartialMmr> for MmrPeaks {
    fn from(partial_mmr: PartialMmr) -> Self {
        // Safety: the [PartialMmr] maintains the constraints the number of true bits in the forest
        // matches the number of peaks, as required by the [MmrPeaks]
        MmrPeaks::new(partial_mmr.forest, partial_mmr.peaks).unwrap()
    }
}

impl From<&MmrPeaks> for PartialMmr {
    fn from(peaks: &MmrPeaks) -> Self {
        Self::from_peaks(peaks.clone())
    }
}

impl From<&PartialMmr> for MmrPeaks {
    fn from(partial_mmr: &PartialMmr) -> Self {
        // Safety: the [PartialMmr] maintains the constraints the number of true bits in the forest
        // matches the number of peaks, as required by the [MmrPeaks]
        MmrPeaks::new(partial_mmr.forest, partial_mmr.peaks.clone()).unwrap()
    }
}

// UTILS
// ================================================================================================

/// Given the description of a `forest`, returns the index of the root element of the smallest tree
/// in it.
pub fn forest_to_root_index(forest: usize) -> InOrderIndex {
    // Count total size of all trees in the forest.
    let nodes = nodes_in_forest(forest);

    // Add the count for the parent nodes that separate each tree. These are allocated but
    // currently empty, and correspond to the nodes that will be used once the trees are merged.
    let open_trees = (forest.count_ones() - 1) as usize;

    // Remove the count of the right subtree of the target tree, target tree root index comes
    // before the subtree for the in-order tree walk.
    let right_subtree_count = ((1u32 << forest.trailing_zeros()) - 1) as usize;

    let idx = nodes + open_trees - right_subtree_count;

    InOrderIndex::new(idx.try_into().unwrap())
}

#[cfg(test)]
mod test {
    use super::forest_to_root_index;
    use crate::merkle::InOrderIndex;

    #[test]
    fn test_forest_to_root_index() {
        fn idx(pos: usize) -> InOrderIndex {
            InOrderIndex::new(pos.try_into().unwrap())
        }

        // When there is a single tree in the forest, the index is equivalent to the number of
        // leaves in that tree, which is `2^n`.
        assert_eq!(forest_to_root_index(0b0001), idx(1));
        assert_eq!(forest_to_root_index(0b0010), idx(2));
        assert_eq!(forest_to_root_index(0b0100), idx(4));
        assert_eq!(forest_to_root_index(0b1000), idx(8));

        assert_eq!(forest_to_root_index(0b0011), idx(5));
        assert_eq!(forest_to_root_index(0b0101), idx(9));
        assert_eq!(forest_to_root_index(0b1001), idx(17));
        assert_eq!(forest_to_root_index(0b0111), idx(13));
        assert_eq!(forest_to_root_index(0b1011), idx(21));
        assert_eq!(forest_to_root_index(0b1111), idx(29));

        assert_eq!(forest_to_root_index(0b0110), idx(10));
        assert_eq!(forest_to_root_index(0b1010), idx(18));
        assert_eq!(forest_to_root_index(0b1100), idx(20));
        assert_eq!(forest_to_root_index(0b1110), idx(26));
    }
}
