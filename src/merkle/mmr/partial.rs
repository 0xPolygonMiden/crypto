use super::{MmrDelta, MmrProof, Rpo256, RpoDigest};
use crate::{
    merkle::{
        mmr::{leaf_to_corresponding_tree, nodes_in_forest},
        InOrderIndex, InnerNodeInfo, MerklePath, MmrError, MmrPeaks,
    },
    utils::{
        collections::{BTreeMap, BTreeSet, Vec},
        vec,
    },
};

// PARTIAL MERKLE MOUNTAIN RANGE
// ================================================================================================
/// Partially materialized Merkle Mountain Range (MMR), used to efficiently store and update the
/// authentication paths for a subset of the elements in a full MMR.
///
/// This structure store only the authentication path for a value, the value itself is stored
/// separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialMmr {
    /// The version of the MMR.
    ///
    /// This value serves the following purposes:
    ///
    /// - The forest is a counter for the total number of elements in the MMR.
    /// - Since the MMR is an append-only structure, every change to it causes a change to the
    ///   `forest`, so this value has a dual purpose as a version tag.
    /// - The bits in the forest also corresponds to the count and size of every perfect binary
    ///   tree that composes the MMR structure, which server to compute indexes and perform
    ///   validation.
    pub(crate) forest: usize,

    /// The MMR peaks.
    ///
    /// The peaks are used for two reasons:
    ///
    /// 1. It authenticates the addition of an element to the [PartialMmr], ensuring only valid
    ///    elements are tracked.
    /// 2. During a MMR update peaks can be merged by hashing the left and right hand sides. The
    ///    peaks are used as the left hand.
    ///
    /// All the peaks of every tree in the MMR forest. The peaks are always ordered by number of
    /// leaves, starting from the peak with most children, to the one with least.
    pub(crate) peaks: Vec<RpoDigest>,

    /// Authentication nodes used to construct merkle paths for a subset of the MMR's leaves.
    ///
    /// This does not include the MMR's peaks nor the tracked nodes, only the elements required
    /// to construct their authentication paths. This property is used to detect when elements can
    /// be safely removed from, because they are no longer required to authenticate any element in
    /// the [PartialMmr].
    ///
    /// The elements in the MMR are referenced using a in-order tree index. This indexing scheme
    /// permits for easy computation of the relative nodes (left/right children, sibling, parent),
    /// which is useful for traversal. The indexing is also stable, meaning that merges to the
    /// trees in the MMR can be represented without rewrites of the indexes.
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
    pub fn from_peaks(peaks: MmrPeaks) -> Self {
        let forest = peaks.num_leaves();
        let peaks = peaks.peaks().to_vec();
        let nodes = BTreeMap::new();
        let track_latest = false;

        Self { forest, peaks, nodes, track_latest }
    }

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    // Gets the current `forest`.
    //
    // This value corresponds to the version of the [PartialMmr] and the number of leaves in it.
    pub fn forest(&self) -> usize {
        self.forest
    }

    // Returns a reference to the current peaks in the [PartialMmr].
    pub fn peaks(&self) -> MmrPeaks {
        // expect() is OK here because the constructor ensures that MMR peaks can be constructed
        // correctly
        MmrPeaks::new(self.forest, self.peaks.clone()).expect("invalid MMR peaks")
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

    // ITERATORS
    // --------------------------------------------------------------------------------------------

    /// Returns an iterator over inner nodes of this [PartialMmr] for the specified leaves.
    ///
    /// The order of iteration is not defined. If a leaf is not presented in this partial MMR it
    /// is silently ignored.
    pub fn inner_nodes<'a, I: Iterator<Item = &'a (usize, RpoDigest)> + 'a>(
        &'a self,
        mut leaves: I,
    ) -> impl Iterator<Item = InnerNodeInfo> + '_ {
        let stack = if let Some((pos, leaf)) = leaves.next() {
            let idx = InOrderIndex::from_leaf_pos(*pos);
            vec![(idx, *leaf)]
        } else {
            Vec::new()
        };

        InnerNodeIterator {
            nodes: &self.nodes,
            leaves,
            stack,
            seen_nodes: BTreeSet::new(),
        }
    }

    // STATE MUTATORS
    // --------------------------------------------------------------------------------------------

    /// Add the authentication path represented by [MerklePath] if it is valid.
    ///
    /// The `index` refers to the global position of the leaf in the MMR, these are 0-indexed
    /// values assigned in a strictly monotonic fashion as elements are inserted into the MMR,
    /// this value corresponds to the values used in the MMR structure.
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
    /// Note: `leaf_pos` corresponds to the position in the MMR and not on an individual tree.
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

// ITERATORS
// ================================================================================================

/// An iterator over every inner node of the [PartialMmr].
pub struct InnerNodeIterator<'a, I: Iterator<Item = &'a (usize, RpoDigest)>> {
    nodes: &'a BTreeMap<InOrderIndex, RpoDigest>,
    leaves: I,
    stack: Vec<(InOrderIndex, RpoDigest)>,
    seen_nodes: BTreeSet<InOrderIndex>,
}

impl<'a, I: Iterator<Item = &'a (usize, RpoDigest)>> Iterator for InnerNodeIterator<'a, I> {
    type Item = InnerNodeInfo;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some((idx, node)) = self.stack.pop() {
            let parent_idx = idx.parent();
            let new_node = self.seen_nodes.insert(parent_idx);

            // if we haven't seen this node's parent before, and the node has a sibling, return
            // the inner node defined by the parent of this node, and move up the branch
            if new_node {
                if let Some(sibling) = self.nodes.get(&idx.sibling()) {
                    let (left, right) = if parent_idx.left_child() == idx {
                        (node, *sibling)
                    } else {
                        (*sibling, node)
                    };
                    let parent = Rpo256::merge(&[left, right]);
                    let inner_node = InnerNodeInfo { value: parent, left, right };

                    self.stack.push((parent_idx, parent));
                    return Some(inner_node);
                }
            }

            // the previous leaf has been processed, try to process the next leaf
            if let Some((pos, leaf)) = self.leaves.next() {
                let idx = InOrderIndex::from_leaf_pos(*pos);
                self.stack.push((idx, *leaf));
            }
        }

        None
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

// TESTS
// ================================================================================================

#[cfg(test)]
mod test {
    use super::{forest_to_root_index, BTreeSet, InOrderIndex, PartialMmr, RpoDigest};
    use crate::merkle::{int_to_node, MerkleStore, Mmr, NodeIndex};

    const LEAVES: [RpoDigest; 7] = [
        int_to_node(0),
        int_to_node(1),
        int_to_node(2),
        int_to_node(3),
        int_to_node(4),
        int_to_node(5),
        int_to_node(6),
    ];

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

    #[test]
    fn test_partial_mmr_inner_nodes_iterator() {
        // build the MMR
        let mmr: Mmr = LEAVES.into();
        let first_peak = mmr.peaks(mmr.forest).unwrap().peaks()[0];

        // -- test single tree ----------------------------

        // get path and node for position 1
        let node1 = mmr.get(1).unwrap();
        let proof1 = mmr.open(1, mmr.forest()).unwrap();

        // create partial MMR and add authentication path to node at position 1
        let mut partial_mmr: PartialMmr = mmr.peaks(mmr.forest()).unwrap().into();
        partial_mmr.add(1, node1, &proof1.merkle_path).unwrap();

        // empty iterator should have no nodes
        assert_eq!(partial_mmr.inner_nodes([].iter()).next(), None);

        // build Merkle store from authentication paths in partial MMR
        let mut store: MerkleStore = MerkleStore::new();
        store.extend(partial_mmr.inner_nodes([(1, node1)].iter()));

        let index1 = NodeIndex::new(2, 1).unwrap();
        let path1 = store.get_path(first_peak, index1).unwrap().path;

        assert_eq!(path1, proof1.merkle_path);

        // -- test no duplicates --------------------------

        // build the partial MMR
        let mut partial_mmr: PartialMmr = mmr.peaks(mmr.forest()).unwrap().into();

        let node0 = mmr.get(0).unwrap();
        let proof0 = mmr.open(0, mmr.forest()).unwrap();

        let node2 = mmr.get(2).unwrap();
        let proof2 = mmr.open(2, mmr.forest()).unwrap();

        partial_mmr.add(0, node0, &proof0.merkle_path).unwrap();
        partial_mmr.add(1, node1, &proof1.merkle_path).unwrap();
        partial_mmr.add(2, node2, &proof2.merkle_path).unwrap();

        // make sure there are no duplicates
        let leaves = [(0, node0), (1, node1), (2, node2)];
        let mut nodes = BTreeSet::new();
        for node in partial_mmr.inner_nodes(leaves.iter()) {
            assert!(nodes.insert(node.value));
        }

        // and also that the store is still be built correctly
        store.extend(partial_mmr.inner_nodes(leaves.iter()));

        let index0 = NodeIndex::new(2, 0).unwrap();
        let index1 = NodeIndex::new(2, 1).unwrap();
        let index2 = NodeIndex::new(2, 2).unwrap();

        let path0 = store.get_path(first_peak, index0).unwrap().path;
        let path1 = store.get_path(first_peak, index1).unwrap().path;
        let path2 = store.get_path(first_peak, index2).unwrap().path;

        assert_eq!(path0, proof0.merkle_path);
        assert_eq!(path1, proof1.merkle_path);
        assert_eq!(path2, proof2.merkle_path);

        // -- test multiple trees -------------------------

        // build the partial MMR
        let mut partial_mmr: PartialMmr = mmr.peaks(mmr.forest()).unwrap().into();

        let node5 = mmr.get(5).unwrap();
        let proof5 = mmr.open(5, mmr.forest()).unwrap();

        partial_mmr.add(1, node1, &proof1.merkle_path).unwrap();
        partial_mmr.add(5, node5, &proof5.merkle_path).unwrap();

        // build Merkle store from authentication paths in partial MMR
        let mut store: MerkleStore = MerkleStore::new();
        store.extend(partial_mmr.inner_nodes([(1, node1), (5, node5)].iter()));

        let index1 = NodeIndex::new(2, 1).unwrap();
        let index5 = NodeIndex::new(1, 1).unwrap();

        let second_peak = mmr.peaks(mmr.forest).unwrap().peaks()[1];

        let path1 = store.get_path(first_peak, index1).unwrap().path;
        let path5 = store.get_path(second_peak, index5).unwrap().path;

        assert_eq!(path1, proof1.merkle_path);
        assert_eq!(path5, proof5.merkle_path);
    }
}
