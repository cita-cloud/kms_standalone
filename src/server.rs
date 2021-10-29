use tokio::task::block_in_place;

use secrecy::SecretVec;

use crate::proto::StatusCode;
use crate::proto::HashDataRequest;
use crate::proto::HashResponse;
use crate::proto::KmsService;
use crate::proto::KmsServiceServer;
use crate::proto::{
    Empty, Hash,
    RawTransactions,
    GetCryptoInfoResponse,
    GenerateKeyPairRequest, GenerateKeyPairResponse,
    VerifyDataHashRequest,
    SignMessageRequest, SignMessageResponse,
    RecoverSignatureRequest, RecoverSignatureResponse,
};

use crate::account::AccountManager;
use crate::sm::{
    Signature,
    sm2_recover_signature,
    sm3_hash,
    pk2address,
    ADDR_BYTES_LEN,
    SM2_SIGNATURE_BYTES_LEN,
    SM3_HASH_BYTES_LEN,
};

const KMS_SERVICE_NAME: &str = "kms_sm";

pub struct CitaCloudKmsService(AccountManager);

impl CitaCloudKmsService {
    pub async fn new(db_uri: &str, master_password: SecretVec<u8>) -> Self {
        Self(AccountManager::new(db_uri, master_password).await)
    }
}

// If you want to know the meaning of those status magic number, 
// go check https://github.com/cita-cloud/status_code.
// Although sometimes you still don't understand it anyway.

#[tonic::async_trait]
impl KmsService for CitaCloudKmsService {
    async fn get_crypto_info(&self, _request: tonic::Request<Empty>) -> Result<tonic::Response<GetCryptoInfoResponse>, tonic::Status> {
        let resp = GetCryptoInfoResponse {
            status: Some(StatusCode { code: 0 }),
            name: KMS_SERVICE_NAME.into(),
            address_len: ADDR_BYTES_LEN as u32,
            hash_len: SM3_HASH_BYTES_LEN as u32,
            signature_len: SM2_SIGNATURE_BYTES_LEN as u32,
        };
        Ok(tonic::Response::new(resp))
    }

    async fn sign_message(&self, request: tonic::Request<SignMessageRequest>) -> Result<tonic::Response<SignMessageResponse>, tonic::Status> {
        let (key_id, msg) = {
            let request = request.into_inner();
            (request.key_id, request.msg)
        };

        let resp = if let Some(sig) = self.0.sign_with(key_id, &msg).await {
            SignMessageResponse {
                status: Some(StatusCode { code: 0}),
                signature: sig.to_vec(),
            }
        } else {
            SignMessageResponse {
                status: Some(StatusCode { code: 302 }),
                signature: vec![],
            }
        };

        Ok(tonic::Response::new(resp))
    }

    async fn hash_data(&self, request: tonic::Request<HashDataRequest>) -> Result<tonic::Response<HashResponse>, tonic::Status> {
        let data = request.into_inner().data;
        // TODO: bench to check if it needs block_in_place
        let hash = block_in_place(||{
            sm3_hash(&data)
        });

        Ok(tonic::Response::new(HashResponse { 
            status: Some(StatusCode { code: 0 }),
            hash: Some(Hash { hash: hash.to_vec() }),
        }))
    }

    async fn generate_key_pair(&self, request: tonic::Request<GenerateKeyPairRequest>) -> Result<tonic::Response<GenerateKeyPairResponse>, tonic::Status> {
        let description = request.into_inner().description;
        let (account_id, address) = self.0.generate_account(&description).await;

        Ok(tonic::Response::new(GenerateKeyPairResponse {
            key_id: account_id,
            address: address.to_vec(),
        }))
    }

    async fn verify_data_hash(&self, request: tonic::Request<VerifyDataHashRequest>) -> Result<tonic::Response<StatusCode>, tonic::Status> {
        let (data, expected_hash) = {
            let request = request.into_inner();
            (request.data, request.hash)
        };

        // TODO: bench to check if it needs block_in_place
        let actual_hash = block_in_place(||{
            sm3_hash(&data)
        });

        let code = if expected_hash == actual_hash {
            0
        } else {
            // just some random error code indicating data hash mismatched
            // that doesn't happen to be in the status code repo.
            /*2*/333
        };

        Ok(tonic::Response::new(StatusCode { code }))
    }

    async fn recover_signature(&self, request: tonic::Request<RecoverSignatureRequest>) -> Result<tonic::Response<RecoverSignatureResponse>, tonic::Status> {
        let (msg, signature) = {
            let request = request.into_inner();
            let signature: Signature = request.signature.try_into()
                .map_err(|_|
                    tonic::Status::invalid_argument("invalid signature length")
                )?;
            (request.msg, signature)
        };

        let resp = {
            let addr = block_in_place(||
                sm2_recover_signature(&msg, &signature)
                    .map(|pk| pk2address(&pk))
            );
            if let Some(addr) = addr {
                RecoverSignatureResponse {
                    status: Some(StatusCode { code: 0}),
                    address: addr.to_vec(),
                }
            } else {
                RecoverSignatureResponse {
                    status: Some(StatusCode { code: 0}),
                    address: vec![],
                }
            }
        };
        Ok(tonic::Response::new(resp))
    }

    async fn check_transactions(&self, _request: tonic::Request<RawTransactions>) -> Result<tonic::Response<StatusCode>, tonic::Status> {
        Err(tonic::Status::unimplemented("This is controller's logic, shouldn't leak to kms"))
    }
}

