use tokio::task::block_in_place;

use anyhow::Result;

use crate::proto::{
    Empty, GenerateKeyPairRequest, GenerateKeyPairResponse, GetCryptoInfoResponse, HashDataRequest,
    HashDataResponse, KmsService, RecoverSignatureRequest, RecoverSignatureResponse,
    SignMessageRequest, SignMessageResponse, SimpleResponse, VerifyDataHashRequest,
};

use crate::account::AccountManager;
use crate::account::Error as AccountError;
use crate::sm::{
    pk2address, sm2_recover_signature, sm3_hash, Signature, ADDR_BYTES_LEN,
    SM2_SIGNATURE_BYTES_LEN, SM3_HASH_BYTES_LEN,
};

const KMS_SERVICE_NAME: &str = "kms_standalone";

pub struct CitaCloudKmsService(AccountManager);

impl CitaCloudKmsService {
    pub fn new(acc_mgr: AccountManager) -> Self {
        Self(acc_mgr)
    }
}

// If you want to know the meaning of those status magic number,
// go check https://github.com/cita-cloud/status_code.
// Although sometimes you still don't understand it anyway.

#[tonic::async_trait]
impl KmsService for CitaCloudKmsService {
    async fn get_crypto_info(
        &self,
        _request: tonic::Request<Empty>,
    ) -> Result<tonic::Response<GetCryptoInfoResponse>, tonic::Status> {
        let resp = GetCryptoInfoResponse {
            name: KMS_SERVICE_NAME.into(),
            address_len: ADDR_BYTES_LEN as u32,
            hash_len: SM3_HASH_BYTES_LEN as u32,
            signature_len: SM2_SIGNATURE_BYTES_LEN as u32,
        };
        Ok(tonic::Response::new(resp))
    }

    async fn sign_message(
        &self,
        request: tonic::Request<SignMessageRequest>,
    ) -> Result<tonic::Response<SignMessageResponse>, tonic::Status> {
        let (key_id, msg) = {
            let request = request.into_inner();
            (request.key_id, request.msg)
        };

        match self.0.sign_with(key_id, &msg).await {
            Ok(sig) => {
                let resp = SignMessageResponse {
                    signature: sig.to_vec(),
                };
                Ok(tonic::Response::new(resp))
            }
            Err(e) => {
                match e.downcast::<AccountError>() {
                    Ok(e @ AccountError::AccountNotFound(_)) => {
                        Err(tonic::Status::not_found(e.to_string()))
                    }
                    Ok(e) => {
                        // This is unreachable in current impl, but for future proof here.
                        Err(tonic::Status::internal(e.to_string()))
                    }
                    Err(e) => {
                        // TODO
                        // log here and consider if it's propriate
                        // to report internal details to client.
                        Err(tonic::Status::internal(e.to_string()))
                    }
                }
            }
        }
    }

    async fn hash_data(
        &self,
        request: tonic::Request<HashDataRequest>,
    ) -> Result<tonic::Response<HashDataResponse>, tonic::Status> {
        let data = request.into_inner().data;
        // TODO: bench to check if it needs block_in_place
        let hash = block_in_place(|| sm3_hash(&data)).to_vec();

        Ok(tonic::Response::new(HashDataResponse { hash }))
    }

    async fn generate_key_pair(
        &self,
        request: tonic::Request<GenerateKeyPairRequest>,
    ) -> Result<tonic::Response<GenerateKeyPairResponse>, tonic::Status> {
        let description = request.into_inner().description;
        let (account_id, address) = self
            .0
            .generate_account(&description)
            .await
            .map_err(|e| tonic::Status::internal(e.to_string()))?;

        Ok(tonic::Response::new(GenerateKeyPairResponse {
            key_id: account_id,
            address: address.to_vec(),
        }))
    }

    async fn verify_data_hash(
        &self,
        request: tonic::Request<VerifyDataHashRequest>,
    ) -> Result<tonic::Response<SimpleResponse>, tonic::Status> {
        let (data, expected_hash) = {
            let request = request.into_inner();
            (request.data, request.hash)
        };

        // TODO: bench to check if it needs block_in_place
        let actual_hash = block_in_place(|| sm3_hash(&data));

        Ok(tonic::Response::new(SimpleResponse {
            is_success: expected_hash == actual_hash,
        }))
    }

    async fn recover_signature(
        &self,
        request: tonic::Request<RecoverSignatureRequest>,
    ) -> Result<tonic::Response<RecoverSignatureResponse>, tonic::Status> {
        let (msg, signature) = {
            let request = request.into_inner();
            let signature: Signature = request
                .signature
                .try_into()
                .map_err(|_| tonic::Status::invalid_argument("invalid signature length"))?;
            (request.msg, signature)
        };

        let resp = {
            let address = block_in_place(|| {
                // We return an empty Vec indicating invalid signature.
                // This behaviour is different from the original kms_sm that returns
                // a status::invalid_argument (which is an abuse of this status)
                sm2_recover_signature(&msg, &signature)
                    .map(|pk| pk2address(&pk).to_vec())
                    .unwrap_or_default()
            });

            RecoverSignatureResponse { address }
        };
        Ok(tonic::Response::new(resp))
    }
}
