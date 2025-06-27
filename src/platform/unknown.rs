use napi::{Error, Result, Status};
use crate::{
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions, 
    PublicKeyCredential
};

pub async fn create_credential_impl(_options: PublicKeyCredentialCreationOptions) -> Result<PublicKeyCredential> {
    Err(Error::new(
        Status::GenericFailure,
        "WebAuthn is not supported on this platform"
    ))
}

pub async fn get_credential_impl(_options: PublicKeyCredentialRequestOptions) -> Result<PublicKeyCredential> {
    Err(Error::new(
        Status::GenericFailure,
        "WebAuthn is not supported on this platform"
    ))
} 

pub async fn is_supported_impl() -> Result<bool> {
    Ok(false)
}