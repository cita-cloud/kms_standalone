mod blockchain {
    tonic::include_proto!("blockchain");
}

mod common {
    tonic::include_proto!("common");
}

mod kms {
    tonic::include_proto!("kms");
}

pub use common::{
    Empty, Hash,
};
pub use blockchain::{
    RawTransactions,
};
pub use kms::kms_service_server::{ KmsService, KmsServiceServer };
pub use kms::HashDataRequest;
pub use kms::GenerateKeyPairRequest;
pub use kms::GenerateKeyPairResponse;
pub use kms::{
    GetCryptoInfoResponse,
    VerifyDataHashRequest,
    SignMessageRequest, SignMessageResponse,
    RecoverSignatureRequest, RecoverSignatureResponse,
};
pub use common::HashResponse;
pub use common::StatusCode;

