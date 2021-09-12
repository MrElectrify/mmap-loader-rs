use crate::offsets::{offset_server::Offset, OffsetsRequest, OffsetsResponse};
use pdb::{FallibleIterator, Source, SymbolData, SymbolTable, PDB};
use reqwest::StatusCode;
use serde_derive::{Deserialize, Serialize};
use std::{borrow::Cow, collections::HashMap, fs::read_to_string, io::Cursor, path::PathBuf};
use tokio::{fs::write, sync::Mutex};
use tonic::{Request, Response, Status};

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct Offsets {
    pub ldrp_hash_table: u32,
    pub ldrp_module_datatable_lock: u32,
    pub ldrp_handle_tls_data: u32,
    pub ldrp_release_tls_entry: u32
}

impl From<OffsetsResponse> for Offsets {
    fn from(off: OffsetsResponse) -> Offsets {
        Offsets {
            ldrp_hash_table: off.ldrp_hash_table,
            ldrp_module_datatable_lock: off.ldrp_module_datatable_lock,
            ldrp_handle_tls_data: off.ldrp_handle_tls_data,
            ldrp_release_tls_entry: off.ldrp_release_tls_entry,
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
        }
    }
}

#[derive(Serialize, Default, Deserialize, Debug)]
pub struct OffsetsDatabase {
    pub offsets: HashMap<String, Offsets>,
}

pub struct OffsetHandler {
    pub database: Mutex<OffsetsDatabase>,
    pub cache_path: PathBuf,
}

impl OffsetHandler {
    pub fn new(cache_path: PathBuf) -> anyhow::Result<OffsetHandler> {
        let database = Mutex::new(match read_to_string(&cache_path) {
            Ok(s) => serde_json::from_str(&s)?,
            _ => OffsetsDatabase::default(),
        });
        Ok(OffsetHandler {
            database,
            cache_path,
        })
    }
}

macro_rules! get_offset {
    ($map:ident, $name:literal) => {
        match $map.get($name) {
            Some(offset) => offset,
            None => {
                eprintln!("Failed to find offset for {}", $name);
                return Ok(None);
            }
        }
    };
}

fn get_offsets_from_pdb_bytes<'a, S: 'a + Source<'a>>(s: S) -> pdb::Result<Option<Offsets>> {
    // parse the pdb
    let mut pdb: PDB<'a, S> = pdb::PDB::open(s)?;
    let symbol_table: SymbolTable<'a> = pdb.global_symbols()?;
    let address_map = pdb.address_map()?;
    let map: HashMap<Cow<str>, u32> = symbol_table
        .iter()
        .map(|sym| sym.parse())
        .filter_map(|data| match data {
            SymbolData::Public(proc) => Ok(Some(proc)),
            _ => Ok(None),
        })
        .filter_map(|proc| match proc.offset.to_rva(&address_map) {
            Some(rva) => Ok(Some((proc.name.to_string(), rva.0))),
            _ => Ok(None),
        })
        .collect()?;
    let ldrp_hash_table = *get_offset!(map, "LdrpHashTable");
    let ldrp_module_datatable_lock = *get_offset!(map, "LdrpModuleDatatableLock");
    let ldrp_handle_tls_data = *get_offset!(map, "LdrpHandleTlsData");
    let ldrp_release_tls_entry = *get_offset!(map, "LdrpReleaseTlsEntry");
    Ok(Some(Offsets {
        ldrp_hash_table,
        ldrp_module_datatable_lock,
        ldrp_handle_tls_data,
        ldrp_release_tls_entry,
    }))
}

#[tonic::async_trait]
impl Offset for OffsetHandler {
    async fn get_offsets(
        &self,
        request: Request<OffsetsRequest>,
    ) -> Result<Response<OffsetsResponse>, Status> {
        let hash = request.into_inner().ntdll_hash;
        // ensure the hex hash is the correct size
        if hash.len() != 33 {
            return Err(Status::invalid_argument("Bad hash length"));
        }
        // see if the hash is valid
        if !hash.chars().all(|x| char::is_ascii_hexdigit(&x)) {
            return Err(Status::invalid_argument("Bad hex digit"));
        }
        let database = &mut self.database.lock().await;
        let offsets_map = &mut database.offsets;
        // see if it is in cache already
        if let Some(offsets) = offsets_map.get(&hash) {
            return Ok(Response::new(offsets.into()));
        }
        // download the PDB
        let pdb = match reqwest::get(format!(
            "http://msdl.microsoft.com/download/symbols/ntdll.pdb/{}/ntdll.pdb",
            &hash
        ))
        .await
        {
            Ok(response) => response,
            Err(e) => {
                return Err(Status::not_found(format!(
                    "Error on fetch: {}",
                    e.to_string()
                )))
            }
        };
        let status = pdb.status();
        match status {
            StatusCode::OK => {}
            StatusCode::NOT_FOUND => {
                return Err(Status::not_found("PDB hash not found"));
            }
            c => {
                return Err(Status::internal(format!("Internal error: {}", c)));
            }
        };
        let pdb = match pdb.bytes().await {
            Ok(bytes) => bytes,
            Err(e) => {
                return Err(Status::internal(format!(
                    "Error on bytes: {}",
                    e.to_string()
                )));
            }
        };
        let offsets = match get_offsets_from_pdb_bytes(Cursor::new(&pdb)) {
            Ok(offsets) => offsets,
            Err(e) => {
                return Err(Status::internal(format!(
                    "Processing error: {}. Bytes: {:?}",
                    e.to_string(),
                    pdb
                )));
            }
        };
        let offsets = match offsets {
            Some(offsets) => offsets,
            None => {
                return Err(Status::internal("Failed to find some functions"));
            }
        };
        // cache the lookup
        offsets_map.insert(hash, offsets);
        // serialize the database
        let s = match serde_json::to_string::<OffsetsDatabase>(&*database) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "Failed to serialize database: {}. DB: {:?}",
                    e.to_string(),
                    database
                );
                return Ok(Response::new(offsets.into()));
            }
        };
        match write(&self.cache_path, &s).await {
            Ok(_) => {}
            Err(e) => {
                eprintln!(
                    "Failed to write database to cache file {}: {}. Payload: {}",
                    &self.cache_path.as_path().to_string_lossy(),
                    e.to_string(),
                    &s
                )
            }
        }
        Ok(Response::new(offsets.into()))
    }
}
