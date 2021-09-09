use crate::offsets;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct Offsets {
    pub ldrp_hash_table: u32,
    pub ldrp_module_datatable_lock: u32,
    pub ldrp_handle_tls_data: u32,
}

impl From<offsets::OffsetsResponse> for Offsets {
    fn from(off: offsets::OffsetsResponse) -> Offsets {
        Offsets {
            ldrp_hash_table: off.ldrp_hash_table,
            ldrp_module_datatable_lock: off.ldrp_module_datatable_lock,
            ldrp_handle_tls_data: off.ldrp_handle_tls_data,
        }
    }
}

impl From<&Offsets> for offsets::OffsetsResponse {
    fn from(off: &Offsets) -> offsets::OffsetsResponse {
        offsets::OffsetsResponse {
            ldrp_hash_table: off.ldrp_hash_table,
            ldrp_module_datatable_lock: off.ldrp_module_datatable_lock,
            ldrp_handle_tls_data: off.ldrp_handle_tls_data,
        }
    }
}

impl From<Offsets> for offsets::OffsetsResponse {
    fn from(off: Offsets) -> offsets::OffsetsResponse {
        offsets::OffsetsResponse {
            ldrp_hash_table: off.ldrp_hash_table,
            ldrp_module_datatable_lock: off.ldrp_module_datatable_lock,
            ldrp_handle_tls_data: off.ldrp_handle_tls_data,
        }
    }
}

#[derive(Serialize, Default, Deserialize, Debug)]
pub struct OffsetsDatabase {
    pub offsets: HashMap<String, Offsets>,
}
