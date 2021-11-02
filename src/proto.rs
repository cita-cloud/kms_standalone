// cita_cloud_proto version v6.2.0
// https://github.com/cita-cloud/cita_cloud_proto

mod blockchain {
    tonic::include_proto!("blockchain");
}

mod common {
    tonic::include_proto!("common");
}

mod kms {
    tonic::include_proto!("kms");
}

pub use common::{Empty, Hash, SimpleResponse};
pub use kms::{
    kms_service_server::{KmsService, KmsServiceServer},
    GenerateKeyPairRequest, GenerateKeyPairResponse, GetCryptoInfoResponse, HashDataRequest,
    HashDataResponse, RecoverSignatureRequest, RecoverSignatureResponse, SignMessageRequest,
    SignMessageResponse, VerifyDataHashRequest,
};
