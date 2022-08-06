use crate::offsets::OffsetsResponse;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct Offsets {
    pub ldrp_hash_table: u32,
    pub ldrp_module_datatable_lock: u32,
    pub ldrp_handle_tls_data: u32,
    pub ldrp_release_tls_entry: u32,
    pub ldrp_mapping_info_index: u32,
    pub ldrp_module_base_address_index: u32,
    pub rtl_initialize_history_table: u32,
}

impl From<OffsetsResponse> for Offsets {
    fn from(off: OffsetsResponse) -> Offsets {
        Offsets {
            ldrp_hash_table: off.ldrp_hash_table,
            ldrp_module_datatable_lock: off.ldrp_module_datatable_lock,
            ldrp_handle_tls_data: off.ldrp_handle_tls_data,
            ldrp_release_tls_entry: off.ldrp_release_tls_entry,
            ldrp_mapping_info_index: off.ldrp_mapping_info_index,
            ldrp_module_base_address_index: off.ldrp_module_base_address_index,
            rtl_initialize_history_table: off.rtl_initialize_history_table,
        }
    }
}

impl From<&Offsets> for OffsetsResponse {
    fn from(off: &Offsets) -> OffsetsResponse {
        OffsetsResponse {
            ldrp_hash_table: off.ldrp_hash_table,
            ldrp_module_datatable_lock: off.ldrp_module_datatable_lock,
            ldrp_handle_tls_data: off.ldrp_handle_tls_data,
            ldrp_release_tls_entry: off.ldrp_release_tls_entry,
            ldrp_mapping_info_index: off.ldrp_mapping_info_index,
            ldrp_module_base_address_index: off.ldrp_module_base_address_index,
            rtl_initialize_history_table: off.rtl_initialize_history_table,
        }
    }
}

impl From<Offsets> for OffsetsResponse {
    fn from(off: Offsets) -> OffsetsResponse {
        OffsetsResponse {
            ldrp_hash_table: off.ldrp_hash_table,
            ldrp_module_datatable_lock: off.ldrp_module_datatable_lock,
            ldrp_handle_tls_data: off.ldrp_handle_tls_data,
            ldrp_release_tls_entry: off.ldrp_release_tls_entry,
            ldrp_mapping_info_index: off.ldrp_mapping_info_index,
            ldrp_module_base_address_index: off.ldrp_module_base_address_index,
            rtl_initialize_history_table: off.rtl_initialize_history_table,
        }
    }
}

#[derive(Serialize, Default, Deserialize, Debug)]
pub struct OffsetsDatabase {
    pub offsets: HashMap<String, Offsets>,
}
