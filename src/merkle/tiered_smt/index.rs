use super::RpoDigest;

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct TreeIndex {
    depth: u32,
    index: u64,
}

impl TreeIndex {
    pub const fn new(depth: u32, index: u64) -> Self {
        Self { depth, index }
    }

    pub const fn root() -> Self {
        Self { depth: 0, index: 0 }
    }

    pub const fn depth(&self) -> u32 {
        self.depth
    }

    pub const fn index(&self) -> u64 {
        self.index
    }

    pub const fn traverse(mut self, right: bool) -> Self {
        self.depth += 1;
        self.index <<= 1;
        self.index += right as u64;
        self
    }

    pub const fn reverse(mut self) -> Self {
        self.depth = self.depth.saturating_sub(1);
        self.index >>= 1;
        self
    }

    pub const fn is_right_sibling(&self) -> bool {
        (self.index & 1) == 1
    }

    pub const fn sibling(mut self) -> Self {
        self.index = if self.is_right_sibling() {
            self.index - 1
        } else {
            self.index + 1
        };
        self
    }

    pub const fn build_node(&self, slf: RpoDigest, sibling: RpoDigest) -> [RpoDigest; 2] {
        if self.is_right_sibling() {
            [sibling, slf]
        } else {
            [slf, sibling]
        }
    }
}
