use anyhow::Result;
use tonic::{Request, Response, Status};

use crate::account::AccountManager;
use crate::proto::{Kms, SignRequest, SignResponse};

pub struct KmsService(AccountManager);

impl KmsService {
    pub fn new(acc_mgr: AccountManager) -> Self {
        Self(acc_mgr)
    }
}

#[tonic::async_trait]
impl Kms for KmsService {
    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        let (account_id, hashes) = {
            let request = request.into_inner();
            (request.account_id, request.msgs)
        };

        self.0
            .sign_with(&account_id, &hashes)
            .await
            .map(|signatures| {
                let resp = SignResponse { signatures };
                Response::new(resp)
            })
            .map_err(|e| Status::internal(e.to_string()))
    }
}
