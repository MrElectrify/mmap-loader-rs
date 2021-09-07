use crate::offsets;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct Offsets {
    pub ldrp_insert_module_to_index: u32,
    pub ldrp_unload_node: u32
}

impl From<offsets::OffsetsResponse> for Offsets {
    fn from(off: offsets::OffsetsResponse) -> Offsets {
        Offsets {
            ldrp_insert_module_to_index: off.ldrp_insert_module_to_index,
            ldrp_unload_node: off.ldrp_unload_node
        }
    }
}

impl From<&Offsets> for offsets::OffsetsResponse {
    fn from(off: &Offsets) -> offsets::OffsetsResponse {
        offsets::OffsetsResponse {
            ldrp_insert_module_to_index: off.ldrp_insert_module_to_index,
            ldrp_unload_node: off.ldrp_unload_node
        }
    }
}

impl From<Offsets> for offsets::OffsetsResponse {
    fn from(off: Offsets) -> offsets::OffsetsResponse {
        offsets::OffsetsResponse {
            ldrp_insert_module_to_index: off.ldrp_insert_module_to_index,
            ldrp_unload_node: off.ldrp_unload_node
        }
    }
}

#[derive(Serialize, Default, Deserialize, Debug)]
pub struct OffsetsDatabase {
    pub offsets: HashMap<String, Offsets>,
}
