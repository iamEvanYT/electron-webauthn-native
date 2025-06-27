use napi::{Result};
use crate::{PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions, PublicKeyCredential};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos::{create_credential_impl, get_credential_impl, is_supported_impl};

#[cfg(not(any(target_os = "macos")))]
mod unknown;
#[cfg(not(any(target_os = "macos")))]
use unknown::{create_credential_impl, get_credential_impl, is_supported_impl};

pub async fn create_credential(options: PublicKeyCredentialCreationOptions) -> Result<PublicKeyCredential> {
    create_credential_impl(options).await
}

pub async fn get_credential(options: PublicKeyCredentialRequestOptions) -> Result<PublicKeyCredential> {
    get_credential_impl(options).await
} 

pub async fn is_supported() -> Result<bool> {
    is_supported_impl().await
}