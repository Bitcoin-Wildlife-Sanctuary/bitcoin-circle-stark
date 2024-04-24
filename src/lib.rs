#![feature(array_chunks)]

use crate::fields::{CM31, M31, QM31};
use bitvm::treepp::pushable::{Builder, Pushable};

pub mod channel;
pub mod channel_commit;
pub mod channel_extract;
pub mod circle;
pub(crate) mod fields;
pub mod merkle_tree;
pub mod prover;
pub mod utils;

impl Pushable for M31 {
    fn bitcoin_script_push(self, builder: Builder) -> Builder {
        self.0.bitcoin_script_push(builder)
    }
}

impl Pushable for CM31 {
    fn bitcoin_script_push(self, builder: Builder) -> Builder {
        let builder = self.0.bitcoin_script_push(builder);
        self.1.bitcoin_script_push(builder)
    }
}

impl Pushable for QM31 {
    fn bitcoin_script_push(self, builder: Builder) -> Builder {
        let builder = self.0.bitcoin_script_push(builder);
        self.1.bitcoin_script_push(builder)
    }
}
