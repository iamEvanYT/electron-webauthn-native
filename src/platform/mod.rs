use napi::Result;
use crate::{PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions, PublicKeyCredential};

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows::{create_credential_impl, get_credential_impl};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos::{create_credential_impl, get_credential_impl};

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
mod unknown;
#[cfg(not(any(target_os = "windows", target_os = "macos")))]
use unknown::{create_credential_impl, get_credential_impl};

pub fn create_credential(options: PublicKeyCredentialCreationOptions) -> Result<PublicKeyCredential> {
    create_credential_impl(options)
}

pub fn get_credential(options: PublicKeyCredentialRequestOptions) -> Result<PublicKeyCredential> {
    get_credential_impl(options)
} 