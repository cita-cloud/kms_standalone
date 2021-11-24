use anyhow::Result;
use tonic::{Request, Response, Status};

use crate::account::AccountManager;
use crate::proto::{
    kms_server::Kms, GetAccountAddressRequest, GetAccountAddressResponse, SignRequest, SignResponse,
};

pub struct KmsService(AccountManager);

impl KmsService {
    pub fn new(acc_mgr: AccountManager) -> Self {
        Self(acc_mgr)
    }
}

#[tonic::async_trait]
impl Kms for KmsService {
    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        let (account_id, messages) = {
            let request = request.into_inner();
            (request.account_id, request.messages)
        };

        self.0
            .sign_with(&account_id, &messages)
            .await
            .map(|signatures| {
                let resp = SignResponse { signatures };
                Response::new(resp)
            })
            .map_err(|e| Status::internal(format!("{:?}", e)))
    }

    async fn get_account_address(
        &self,
        request: Request<GetAccountAddressRequest>,
    ) -> Result<Response<GetAccountAddressResponse>, Status> {
        let account_id = request.into_inner().account_id;
        self.0
            .get_account_address(&account_id)
            .await
            .map(|addr| {
                let address = format!("0x{}", hex::encode(&addr));
                let resp = GetAccountAddressResponse { address };
                Response::new(resp)
            })
            .map_err(|e| Status::internal(format!("{:?}", e)))
    }
}
