use napi::{Result, Error, Status};
use napi::bindgen_prelude::*;
use crate::{
    PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions, 
    PublicKeyCredential
};

pub fn create_credential_impl(_options: PublicKeyCredentialCreationOptions) -> Result<PublicKeyCredential> {
    Err(Error::new(
        Status::GenericFailure,
        "WebAuthn is not supported on this platform"
    ))
}

pub fn get_credential_impl(_options: PublicKeyCredentialRequestOptions) -> Result<PublicKeyCredential> {
    Err(Error::new(
        Status::GenericFailure,
        "WebAuthn is not supported on this platform"
    ))
} 