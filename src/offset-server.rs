mod db;
mod offsets;
use crate::db::{
    Offsets, OffsetsDatabase
};
use offsets::{
    offset_server::{Offset, OffsetServer},
    {OffsetsRequest, OffsetsResponse},
};
use pdb::{FallibleIterator, Source, SymbolData, SymbolTable, PDB};
use reqwest::StatusCode;
use std::{borrow::Cow, collections::HashMap, env, io::Cursor, net::SocketAddr};
use tokio::{
    fs::{read_to_string, write},
    sync::Mutex,
};
use tonic::{transport::Server, Request, Response, Status};

#[derive(Debug)]
struct OffsetHandler {
    database: Mutex<OffsetsDatabase>,
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
            SymbolData::Public(proc) if proc.function => Ok(Some(proc)),
            _ => Ok(None),
        })
        .filter_map(|proc| match proc.offset.to_rva(&address_map) {
            Some(rva) => Ok(Some((proc.name.to_string(), rva.0))),
            _ => Ok(None),
        })
        .collect()?;
    let ldrp_insert_module_to_index = *get_offset!(map, "LdrpInsertModuleToIndex");
    let ldrp_unload_node = *get_offset!(map, "LdrpUnloadNode");
    Ok(Some(Offsets {
        ldrp_insert_module_to_index,
        ldrp_unload_node
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
        match write("db.json", &s).await {
            Ok(_) => {}
            Err(e) => {
                eprintln!(
                    "Failed to write database to db.json: {}. Payload: {}",
                    e.to_string(),
                    &s
                )
            }
        }
        Ok(Response::new(offsets.into()))
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args: Vec<String> = env::args().collect();
    if args.len() > 3 {
        eprintln!("Usage: {} <address:ipv4> <port:u16>", args[0]);
        return Ok(());
    }
    let addr = match args.get(1) {
        Some(addr) => addr.parse(),
        None => "0.0.0.0".parse(),
    }?;
    let port = match args.get(2) {
        Some(addr) => addr.parse(),
        None => "42220".parse(),
    }?;
    let database = Mutex::new(match read_to_string("db.json").await {
        Ok(s) => serde_json::from_str(&s)?,
        _ => OffsetsDatabase::default(),
    });
    let offset_handler = OffsetHandler { database };
    Server::builder()
        .add_service(OffsetServer::new(offset_handler))
        .serve(SocketAddr::new(addr, port))
        .await?;
    Ok(())
}

#[cfg(test)]
mod test {
    macro_rules! hashmap {
        ($( $key: expr => $val: expr ),*) => {{
             let mut map = ::std::collections::HashMap::new();
             $( map.insert($key, $val); )*
             map
        }}
    }

    use super::*;

    #[tokio::test]
    async fn hash_length() {
        let database = Mutex::new(OffsetsDatabase::default());
        let offset_handler = OffsetHandler { database };
        let request = Request::new(OffsetsRequest {
            ntdll_hash: "123".into(),
        });
        let err = offset_handler.get_offsets(request).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(err.message(), "Bad hash length");
    }

    #[tokio::test]
    async fn hash_digits() {
        let database = Mutex::new(OffsetsDatabase::default());
        let offset_handler = OffsetHandler { database };
        let request = Request::new(OffsetsRequest {
            ntdll_hash: "46F6F5C30E7147E46F2A953A5DAF201AG".into(),
        });
        let err = offset_handler.get_offsets(request).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(err.message(), "Bad hex digit");
    }

    #[tokio::test]
    async fn not_found() {
        let database = Mutex::new(OffsetsDatabase::default());
        let offset_handler = OffsetHandler { database };
        let request = Request::new(OffsetsRequest {
            ntdll_hash: "46F6F5C30E7147E46F2A953A5DAF201A2".into(),
        });
        let err = offset_handler.get_offsets(request).await.unwrap_err();
        println!("Err: {:?}", err);
    }

    #[tokio::test]
    async fn good_fetch() {
        let database = Mutex::new(OffsetsDatabase::default());
        let offset_handler = OffsetHandler { database };
        let request = Request::new(OffsetsRequest {
            ntdll_hash: "46F6F5C30E7147E46F2A953A5DAF201A1".into(),
        });
        let response = offset_handler
            .get_offsets(request)
            .await
            .unwrap()
            .into_inner();
        // ensure it was cached
        assert!(offset_handler
            .database
            .lock()
            .await
            .offsets
            .contains_key("46F6F5C30E7147E46F2A953A5DAF201A1"));
        assert_eq!(response.ldrp_insert_module_to_index, 0x7FD40);
        assert_eq!(response.ldrp_unload_node, 0x6A3E8);
    }

    #[tokio::test]
    async fn good_cache() {
        let database = Mutex::new(OffsetsDatabase {
            offsets: hashmap!("46F6F5C30E7147E46F2A953A5DAF201A1".into() => Offsets{
            ldrp_insert_module_to_index: 1,
            ldrp_unload_node: 2
            }),
        });
        let offset_handler = OffsetHandler { database };
        let request = Request::new(OffsetsRequest {
            ntdll_hash: "46F6F5C30E7147E46F2A953A5DAF201A1".into(),
        });
        let response = offset_handler
            .get_offsets(request)
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.ldrp_insert_module_to_index, 1);
        assert_eq!(response.ldrp_unload_node, 2);
    }
}
