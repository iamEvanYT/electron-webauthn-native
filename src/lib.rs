#![deny(clippy::all)]

mod platform;

use napi::bindgen_prelude::*;
use napi::Result;
use std::collections::HashMap;

use napi_derive::napi;

// WebAuthn data structures
#[napi(object)]
pub struct AuthenticationExtensionsPRFInputs {
    #[napi(ts_type = "AuthenticationExtensionsPRFValues | undefined")]
    pub eval: Option<AuthenticationExtensionsPRFValues>,
    #[napi(ts_type = "Record<string, AuthenticationExtensionsPRFValues> | undefined")]
    pub eval_by_credential: Option<HashMap<String, AuthenticationExtensionsPRFValues>>,
}

#[napi(object)]
pub struct AuthenticationExtensionsPRFValues {
    pub first: Buffer,
    #[napi(ts_type = "Buffer | undefined")]
    pub second: Option<Buffer>,
}

#[napi(object)]
pub struct PublicKeyCredentialDescriptor {
    pub id: Buffer,
    #[napi(ts_type = "Array<string> | undefined")]
    pub transports: Option<Vec<String>>,
    #[napi(js_name = "type")]
    pub type_: String,
}

#[napi(object)]
pub struct AuthenticationExtensionsClientInputs {
    #[napi(ts_type = "string | undefined")]
    pub appid: Option<String>,
    #[napi(ts_type = "boolean | undefined")]
    pub cred_props: Option<bool>,
    #[napi(ts_type = "boolean | undefined")]
    pub hmac_create_secret: Option<bool>,
    #[napi(ts_type = "boolean | undefined")]
    pub min_pin_length: Option<bool>,
    #[napi(ts_type = "AuthenticationExtensionsPRFInputs | undefined")]
    pub prf: Option<AuthenticationExtensionsPRFInputs>,
}

#[napi(object)]
pub struct PublicKeyCredentialParameters {
    pub alg: i32,
    #[napi(js_name = "type")]
    pub type_: String,
}

#[napi(object)]
pub struct PublicKeyCredentialEntity {
    pub name: String,
}

#[napi(object)]
pub struct PublicKeyCredentialRpEntity {
    #[napi(ts_type = "string | undefined")]
    pub id: Option<String>,
    pub name: String,
}

#[napi(object)]
pub struct PublicKeyCredentialUserEntity {
    pub display_name: String,
    pub id: Buffer,
    pub name: String,
}

#[napi(object)]
pub struct AuthenticatorSelectionCriteria {
    #[napi(ts_type = "string | undefined")]
    pub authenticator_attachment: Option<String>,
    #[napi(ts_type = "boolean | undefined")]
    pub require_resident_key: Option<bool>,
    #[napi(ts_type = "string | undefined")]
    pub resident_key: Option<String>,
    #[napi(ts_type = "\"discouraged\" | \"preferred\" | \"required\" | undefined")]
    pub user_verification: Option<String>,
}

#[napi(object)]
pub struct PublicKeyCredentialCreationOptions {
    #[napi(ts_type = "\"direct\" | \"enterprise\" | \"indirect\" | \"none\" | undefined")]
    pub attestation: Option<String>,
    #[napi(ts_type = "AuthenticatorSelectionCriteria | undefined")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub challenge: Buffer,
    #[napi(ts_type = "Array<PublicKeyCredentialDescriptor> | undefined")]
    pub exclude_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    #[napi(ts_type = "AuthenticationExtensionsClientInputs | undefined")]
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub rp: PublicKeyCredentialRpEntity,
    #[napi(ts_type = "number | undefined")]
    pub timeout: Option<i32>,
    pub user: PublicKeyCredentialUserEntity,
}

#[napi(object)]
pub struct PublicKeyCredentialRequestOptions {
    #[napi(ts_type = "Array<PublicKeyCredentialDescriptor> | undefined")]
    pub allow_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    pub challenge: Buffer,
    #[napi(ts_type = "AuthenticationExtensionsClientInputs | undefined")]
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
    #[napi(ts_type = "string | undefined")]
    pub rp_id: Option<String>,
    #[napi(ts_type = "number | undefined")]
    pub timeout: Option<i32>,
    #[napi(ts_type = "\"discouraged\" | \"preferred\" | \"required\" | undefined")]
    pub user_verification: Option<String>,
}

#[napi(object)]
pub struct PublicKeyCredential {
    pub id: String,
    pub raw_id: Buffer,
    // Simplified response - can be extended based on needs
    pub response: Buffer,
    #[napi(ts_type = "string | undefined")]
    pub authenticator_attachment: Option<String>,
    #[napi(js_name = "type")]
    pub type_: String,
}

/// Create a new WebAuthn credential
#[napi]
pub async fn create(options: PublicKeyCredentialCreationOptions) -> Result<PublicKeyCredential> {
    platform::create_credential(options).await
}

/// Get/authenticate with an existing WebAuthn credential
#[napi]
pub async fn get(options: PublicKeyCredentialRequestOptions) -> Result<PublicKeyCredential> {
    platform::get_credential(options).await
}

#[napi]
pub async fn is_supported() -> Result<bool> {
    platform::is_supported().await
}