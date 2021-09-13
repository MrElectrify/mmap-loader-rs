use crate::{db::OffsetHandler, offsets::offset_server::OffsetServer};
use std::{net::SocketAddr, path::PathBuf};
use tonic::{
    transport,
    transport::{Identity, ServerTlsConfig},
};

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
    pub fn new(
        endpoint: SocketAddr,
        cache_path: PathBuf,
        tls_identity: Option<Identity>,
    ) -> Result<Server, anyhow::Error> {
        Ok(Server {
            handler: OffsetHandler::new(cache_path)?,
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::offsets::{offset_server::Offset, OffsetsRequest};
    use tonic::Request;

    #[tokio::test]
    async fn hash_length() {
        let endpoint = SocketAddr::new("127.0.0.1".parse().unwrap(), 42220);
        let cache_path = "test/cache.json".into();
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
        let cache_path = "test/cache.json".into();
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
        let cache_path = "test/cache.json".into();
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
        let cache_path = "test/cache.json".into();
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
