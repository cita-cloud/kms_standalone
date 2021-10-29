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
pub use blockchain::RawTransactions;
pub use kms::{
    kms_service_server::{ KmsService, KmsServiceServer },
    GetCryptoInfoResponse,
    HashDataRequest,
    VerifyDataHashRequest,
    SignMessageRequest, SignMessageResponse,
    GenerateKeyPairRequest, GenerateKeyPairResponse,
    RecoverSignatureRequest, RecoverSignatureResponse,
};
pub use common::HashResponse;
pub use common::StatusCode;

