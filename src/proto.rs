mod kms {
    tonic::include_proto!("kms");
}

pub use kms::{
    kms_server::{Kms, KmsServer},
    SignRequest, SignResponse,
};
