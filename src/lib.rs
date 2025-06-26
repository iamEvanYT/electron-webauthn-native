#![deny(clippy::all)]

#[macro_use]
extern crate napi_derive;

mod platform;

use napi::bindgen_prelude::*;
use napi::Result;

// WebAuthn data structures
#[napi(object)]
pub struct PublicKeyCredentialRpEntity {
    #[napi(ts_type = "string | undefined")]
    pub id: Option<String>,
    pub name: String,
}

#[napi(object)]
pub struct PublicKeyCredentialUserEntity {
    pub id: Buffer,
    pub name: String,
    pub display_name: String,
}

#[napi(object)]
pub struct PublicKeyCredentialParameters {
    #[napi(js_name = "type")]
    pub type_: String,
    pub alg: i32,
}

#[napi(object)]
pub struct AuthenticatorSelectionCriteria {
    #[napi(ts_type = "string | undefined")]
    pub authenticator_attachment: Option<String>,
    #[napi(ts_type = "boolean | undefined")]
    pub require_resident_key: Option<bool>,
    #[napi(ts_type = "string | undefined")]
    pub resident_key: Option<String>,
    #[napi(ts_type = "string | undefined")]
    pub user_verification: Option<String>,
}

#[napi(object)]
pub struct PublicKeyCredentialDescriptor {
    #[napi(js_name = "type")]
    pub type_: String,
    pub id: Buffer,
    #[napi(ts_type = "Array<string> | undefined")]
    pub transports: Option<Vec<String>>,
}

#[napi(object)]
pub struct PublicKeyCredentialCreationOptions {
    pub rp: PublicKeyCredentialRpEntity,
    pub user: PublicKeyCredentialUserEntity,
    pub challenge: Buffer,
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    #[napi(ts_type = "number | undefined")]
    pub timeout: Option<i32>,
    #[napi(ts_type = "Array<PublicKeyCredentialDescriptor> | undefined")]
    pub exclude_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    #[napi(ts_type = "AuthenticatorSelectionCriteria | undefined")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[napi(ts_type = "string | undefined")]
    pub attestation: Option<String>,
}

#[napi(object)]
pub struct PublicKeyCredentialRequestOptions {
    pub challenge: Buffer,
    #[napi(ts_type = "number | undefined")]
    pub timeout: Option<i32>,
    #[napi(ts_type = "string | undefined")]
    pub rp_id: Option<String>,
    #[napi(ts_type = "Array<PublicKeyCredentialDescriptor> | undefined")]
    pub allow_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    #[napi(ts_type = "string | undefined")]
    pub user_verification: Option<String>,
}

#[napi(object)]
pub struct AuthenticatorAttestationResponse {
    pub client_data_json: Buffer,
    pub attestation_object: Buffer,
    pub transports: Vec<String>,
}

#[napi(object)]
pub struct AuthenticatorAssertionResponse {
    pub client_data_json: Buffer,
    pub authenticator_data: Buffer,
    pub signature: Buffer,
    #[napi(ts_type = "Buffer | undefined")]
    pub user_handle: Option<Buffer>,
}

#[napi(object)]
pub struct PublicKeyCredential {
    pub id: String,
    pub raw_id: Buffer,
    pub response: Either<AuthenticatorAttestationResponse, AuthenticatorAssertionResponse>,
    #[napi(ts_type = "string | undefined")]
    pub authenticator_attachment: Option<String>,
    #[napi(js_name = "type")]
    pub type_: String,
}

/// Create a new WebAuthn credential
#[napi]
pub fn create(options: PublicKeyCredentialCreationOptions) -> Result<PublicKeyCredential> {
    platform::create_credential(options)
}

/// Get/authenticate with an existing WebAuthn credential
#[napi]
pub fn get(options: PublicKeyCredentialRequestOptions) -> Result<PublicKeyCredential> {
    platform::get_credential(options)
}
