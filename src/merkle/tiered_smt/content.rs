use super::RpoDigest;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ContentType {
    Empty,
    Internal,
    Leaf,
}

impl ContentType {
    pub const fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }

    pub const fn is_internal(&self) -> bool {
        matches!(self, Self::Internal)
    }

    pub const fn is_leaf(&self) -> bool {
        matches!(self, Self::Leaf)
    }
}

impl Default for ContentType {
    fn default() -> Self {
        Self::Empty
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct Content {
    r#type: ContentType,
    digest: RpoDigest,
}

impl Content {
    pub const fn internal(digest: RpoDigest) -> Self {
        Self {
            r#type: ContentType::Internal,
            digest,
        }
    }

    pub const fn leaf(digest: RpoDigest) -> Self {
        Self {
            r#type: ContentType::Leaf,
            digest,
        }
    }

    pub const fn r#type(&self) -> ContentType {
        self.r#type
    }

    pub const fn digest(&self) -> &RpoDigest {
        &self.digest
    }
}
