use napi::Result;
use napi::bindgen_prelude::*;
use napi::{Error, Status};
use crate::{
    PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions, 
    PublicKeyCredential, AuthenticatorAttestationResponse, AuthenticatorAssertionResponse
};

pub fn create_credential_impl(_options: PublicKeyCredentialCreationOptions) -> Result<PublicKeyCredential> {
    Err(Error::new(
        Status::GenericFailure,
        "Windows WebAuthn implementation is not yet available. Please check for updates or use a different platform."
    ))
}

pub fn get_credential_impl(_options: PublicKeyCredentialRequestOptions) -> Result<PublicKeyCredential> {
    Err(Error::new(
        Status::GenericFailure,
        "Windows WebAuthn implementation is not yet available. Please check for updates or use a different platform."
    ))
} 