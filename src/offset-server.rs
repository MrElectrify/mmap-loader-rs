pub mod offsets {
    tonic::include_proto!("mmap");
}

use offsets::{
    offset_server::{Offset, OffsetServer},
    {OffsetsRequest, OffsetsResponse},
};
use serde_derive::{Deserialize, Serialize};
use std::{collections::HashMap, fs::File, io::BufReader};
use tokio::sync::Mutex;
use tonic::{transport::Server, Request, Response, Status};

#[derive(Serialize, Deserialize, Debug)]
struct Offsets {
    ldrp_insert_data_table_entry: u64,
    ldrp_insert_module_to_index: u64,
    ldrp_handle_tls_data: u64,
    rtl_insert_inverted_function_table: u64,
}

#[derive(Serialize, Default, Deserialize, Debug)]
struct OffsetsDatabase {
    offsets: HashMap<String, Offsets>,
}

#[derive(Debug)]
struct OffsetHandler {
    database: Mutex<OffsetsDatabase>,
}

#[tonic::async_trait]
impl Offset for OffsetHandler {
    async fn get_offsets(
        &self,
        request: Request<OffsetsRequest>,
    ) -> Result<Response<OffsetsResponse>, Status> {
        let hash = &request.into_inner().ntdll_hash;
        // ensure the hex hash is the correct size
        if hash.len() != 33 {
            return Err(Status::invalid_argument("Bad hash length"));
        }
        // see if the hash is valid
        if !hash.chars().all(|x| char::is_ascii_hexdigit(&x)) {
            return Err(Status::invalid_argument("Bad hex digit"));
        }
        if let Some(offsets) = self.database.lock().await.offsets.get(hash) {
            return Ok(Response::new(OffsetsResponse {
                ldrp_insert_data_table_entry: offsets.ldrp_insert_data_table_entry,
                ldrp_insert_module_to_index: offsets.ldrp_insert_module_to_index,
                ldrp_handle_tls_data: offsets.ldrp_handle_tls_data,
                rtl_insert_inverted_function_table: offsets.rtl_insert_inverted_function_table,
            }));
        }
        // lock the database and search for the hash
        Ok(Response::new(OffsetsResponse::default()))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "0.0.0.0:37756".parse()?;
    let database = Mutex::new(match File::open("db.json") {
        Ok(f) => serde_json::from_reader(BufReader::new(f))?,
        Err(_) => OffsetsDatabase::default(),
    });
    let offset_handler = OffsetHandler { database };
    Server::builder()
        .add_service(OffsetServer::new(offset_handler))
        .serve(addr)
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
        let response = offset_handler.get_offsets(request).await.unwrap_err();
        assert_eq!(response.code(), tonic::Code::InvalidArgument);
        assert_eq!(response.message(), "Bad hash length");
    }

    #[tokio::test]
    async fn hash_digits() {
        let database = Mutex::new(OffsetsDatabase::default());
        let offset_handler = OffsetHandler { database };
        let request = Request::new(OffsetsRequest {
            ntdll_hash: "46F6F5C30E7147E46F2A953A5DAF201AG".into(),
        });
        let response = offset_handler.get_offsets(request).await.unwrap_err();
        assert_eq!(response.code(), tonic::Code::InvalidArgument);
        assert_eq!(response.message(), "Bad hex digit");
    }

    #[tokio::test]
    async fn good() {
        let database = Mutex::new(OffsetsDatabase {
            offsets: hashmap!("46F6F5C30E7147E46F2A953A5DAF201A1".into() => Offsets{
            ldrp_insert_data_table_entry: 1,
            ldrp_insert_module_to_index: 2,
            ldrp_handle_tls_data: 3,
            rtl_insert_inverted_function_table: 4,
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
        assert_eq!(response.ldrp_insert_data_table_entry, 1);
        assert_eq!(response.ldrp_insert_module_to_index, 2);
        assert_eq!(response.ldrp_handle_tls_data, 3);
        assert_eq!(response.rtl_insert_inverted_function_table, 4);
    }
}
