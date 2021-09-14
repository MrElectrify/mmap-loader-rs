use crate::{
    db::{
        Offsets, OffsetsDatabase
    }, 
    offsets::{
        OffsetsRequest, OffsetsResponse, 
        offset_server::{
            Offset, OffsetServer
        }
    }
};
use pdb::{FallibleIterator, Source, SymbolData, SymbolTable, PDB};
use reqwest::StatusCode;
use tokio::sync::Mutex;
use std::{borrow::Cow, collections::HashMap, fs::read_to_string, io::Cursor, net::SocketAddr, path::PathBuf};
use tokio::fs::write;
use tonic::{
    transport,
    transport::{Identity, ServerTlsConfig},
    Request,
    Response,
    Status
};

/// The actual handler for Offset requests. Owns an internal database
pub struct OffsetHandler {
    pub database: Mutex<OffsetsDatabase>,
    pub cache_path: PathBuf,
}

/// An offset server that parses PDBs and sends the parsed addresses to the client
pub struct Server {
    handler: OffsetHandler,
    endpoint: SocketAddr,
    tls_identity: Option<Identity>,
}

impl Server {
    /// Creates a new server on an endpoint, with a JSON cache
    /// stored at the `cache_path`
    ///
    /// # Arguments
    ///
    /// `endpoint`: The network address to bind to
    ///
    /// `cache_path`: The path to the JSON cache. Will be created if it does not exist
    ///
    /// `tls_identity`: The TLS identity. If this is specified, TLS will be used with
    /// the given certificate and private key
    pub fn new<S: AsRef<str>>(
        endpoint: SocketAddr,
        cache_path: S,
        tls_identity: Option<Identity>,
    ) -> Result<Server, anyhow::Error> {
        Ok(Server {
            handler: OffsetHandler::new(cache_path.as_ref().into())?,
            endpoint,
            tls_identity,
        })
    }

    /// Runs the server
    pub async fn run(self) -> Result<(), anyhow::Error> {
        let endpoint = self.endpoint;
        let mut server = transport::Server::builder();
        if let Some(tls_identity) = self.tls_identity {
            server = server.tls_config(ServerTlsConfig::new().identity(tls_identity))?;
        }
        server
            .add_service(OffsetServer::new(self.handler))
            .serve(endpoint)
            .await?;
        Ok(())
    }
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

/// Gets an offset in the PDB file
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

/// Gets all of the offsets from the ntdll PDB
///
/// # Arguments
///
/// `s`: The source PDB bytes
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
    let ldrp_mapping_info_index = *get_offset!(map, "LdrpMappingInfoIndex");
    let ldrp_module_base_address_index = *get_offset!(map, "LdrpModuleBaseAddressIndex");
    Ok(Some(Offsets {
        ldrp_hash_table,
        ldrp_module_datatable_lock,
        ldrp_handle_tls_data,
        ldrp_release_tls_entry,
        ldrp_mapping_info_index,
        ldrp_module_base_address_index,
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::offsets::{offset_server::Offset, OffsetsRequest};
    use tonic::Request;

    #[tokio::test]
    async fn hash_length() {
        let endpoint = SocketAddr::new("127.0.0.1".parse().unwrap(), 42220);
        let cache_path = "test/cache.json";
        let server = Server::new(endpoint, cache_path, None).unwrap();
        let request = Request::new(OffsetsRequest {
            ntdll_hash: "123".into(),
        });
        let err = server.handler.get_offsets(request).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(err.message(), "Bad hash length");
    }

    #[tokio::test]
    async fn hash_digits() {
        let endpoint = SocketAddr::new("127.0.0.1".parse().unwrap(), 42220);
        let cache_path = "test/cache.json";
        let server = Server::new(endpoint, cache_path, None).unwrap();
        let request = Request::new(OffsetsRequest {
            ntdll_hash: "46F6F5C30E7147E46F2A953A5DAF201AG".into(),
        });
        let err = server.handler.get_offsets(request).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(err.message(), "Bad hex digit");
    }

    #[tokio::test]
    async fn not_found() {
        let endpoint = SocketAddr::new("127.0.0.1".parse().unwrap(), 42220);
        let cache_path = "test/cache.json";
        let server = Server::new(endpoint, cache_path, None).unwrap();
        let request = Request::new(OffsetsRequest {
            ntdll_hash: "46F6F5C30E7147E46F2A953A5DAF201A2".into(),
        });
        let err = server.handler.get_offsets(request).await.unwrap_err();
        assert_eq!(err.message(), "PDB hash not found");
    }

    #[tokio::test]
    async fn good_fetch() {
        let endpoint = SocketAddr::new("127.0.0.1".parse().unwrap(), 42220);
        let cache_path = "test/cache.json";
        let server = Server::new(endpoint, cache_path, None).unwrap();
        let request = Request::new(OffsetsRequest {
            ntdll_hash: "46F6F5C30E7147E46F2A953A5DAF201A1".into(),
        });
        let response = server
            .handler
            .get_offsets(request)
            .await
            .unwrap()
            .into_inner();
        // ensure it was cached
        assert!(server
            .handler
            .database
            .lock()
            .await
            .offsets
            .contains_key("46F6F5C30E7147E46F2A953A5DAF201A1"));
        assert_eq!(response.ldrp_hash_table, 0x16A140);
        assert_eq!(response.ldrp_module_datatable_lock, 0x16B240);
        assert_eq!(response.ldrp_handle_tls_data, 0x47C14);
    }
}
