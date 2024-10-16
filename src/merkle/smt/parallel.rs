use std::{
    cmp::Ordering,
    collections::BTreeMap,
    sync::{Arc, LazyLock},
    thread,
};

use crate::merkle::smt::{InnerNode, MutationSet, NodeIndex, SparseMerkleTree};

static TASK_COUNT: LazyLock<usize> = LazyLock::new(|| {
    // FIXME: error handling?
    thread::available_parallelism().unwrap().get()
});

#[allow(dead_code)]
pub(crate) trait ParallelSparseMerkleTree<const DEPTH: u8>
where
    // Note: these type bounds need to be specified this way or we'll have to duplicate them
    // everywhere.
    // https://github.com/rust-lang/rust/issues/130805.
    Self: SparseMerkleTree<
        DEPTH,
        Key: Send + Sync + 'static,
        Value: Send + Sync + 'static,
        Leaf: Send + Sync + 'static,
    >,
{
    /// Shortcut for [`ParallelSparseMerkleTree::compute_mutations_parallel_n()`] with an
    /// automatically determined number of tasks.
    ///
    /// Currently, the default number of tasks is the return value of
    /// [`std::thread::available_parallelism()`], but this may be subject to change in the future.
    async fn compute_mutations_parallel<I>(
        &self,
        kv_pairs: I,
    ) -> MutationSet<DEPTH, Self::Key, Self::Value>
    where
        I: IntoIterator<Item = (Self::Key, Self::Value)>,
    {
        self.compute_mutations_parallel_n(kv_pairs, *TASK_COUNT).await
    }

    async fn compute_mutations_parallel_n<I>(
        &self,
        _kv_pairs: I,
        _tasks: usize,
    ) -> MutationSet<DEPTH, Self::Key, Self::Value>
    where
        I: IntoIterator<Item = (Self::Key, Self::Value)>,
    {
        todo!();
    }

    fn get_inner_nodes(&self) -> Arc<BTreeMap<NodeIndex, InnerNode>>;
    fn get_leaves(&self) -> Arc<BTreeMap<u64, Self::Leaf>>;
    fn get_leaf_value(_leaf: &Self::Leaf, _key: &Self::Key) -> Option<Self::Value> {
        todo!();
    }
    fn cmp_keys(_lhs: &Self::Key, _rhs: &Self::Key) -> Ordering {
        todo!();
    }
}
