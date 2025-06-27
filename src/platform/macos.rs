//! macOS WebAuthn / Passkey glue using Apple AuthenticationServices (Ventura+)
//! ---------------------------------------------------------------------------
//! This file provides the synchronous `create_credential_impl` and
//! `get_credential_impl` helpers used by the napi‐rs layer.  Internally we
//! exercise the Objective‑C `ASAuthorizationPlatformPublicKeyCredentialProvider`
//! API when it is available; outside unit tests we still fall back to a fully
//! in‑process mock so that the Rust crate can build and unit‑test on CI without
//! real macOS UI interaction.  Swap the mock for a real async delegate when
//! ready.

#![cfg(target_os = "macos")]
#![allow(non_snake_case, clippy::needless_return)]

use objc::rc::{autoreleasepool};
use objc::{msg_send, sel, sel_impl};
use objc::runtime::{Class, Object};

use objc_foundation::{INSData, INSString, NSData, NSString};

use napi::{bindgen_prelude::*, Error, Result, Status};

use crate::{
    AuthenticatorAssertionResponse, AuthenticatorAttestationResponse, PublicKeyCredential,
    PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
};

use base64::Engine; // bring the `encode` method into scope

// -------------------------------------------------------------------------------------------------
//  Public entry points (called from the JS bindings layer)
// -------------------------------------------------------------------------------------------------

/// Register a new credential ("makeCredential" in WebAuthn).
///
/// This implementation is *synchronous* but runs inside an autorelease‑pool.
pub fn create_credential_impl(opts: PublicKeyCredentialCreationOptions) -> Result<PublicKeyCredential> {
    autoreleasepool(|| create_credential_inner(opts))
}

/// Get an assertion from an existing credential ("getAssertion" in WebAuthn).
pub fn get_credential_impl(opts: PublicKeyCredentialRequestOptions) -> Result<PublicKeyCredential> {
    autoreleasepool(|| get_credential_inner(opts))
}

// -------------------------------------------------------------------------------------------------
//  Private helpers – minimal, blocking implementation with a mock happy‑path.
// -------------------------------------------------------------------------------------------------

fn create_credential_inner(opts: PublicKeyCredentialCreationOptions) -> Result<PublicKeyCredential> {
    unsafe {
        // ── 1. Availability check ────────────────────────────────────────────────────────────────
        let provider_cls = Class::get("ASAuthorizationPlatformPublicKeyCredentialProvider").ok_or_else(||
            Error::new(Status::GenericFailure, "ASAuthorizationPlatformPublicKeyCredentialProvider not available (needs macOS 13+)")
        )?;

        // ── 2. Build provider ────────────────────────────────────────────────────────────────────
        let rp_id = opts.rp.id.as_deref().ok_or_else(|| Error::new(Status::InvalidArg, "RP ID is required"))?;
        let rp_ns  = NSString::from_str(rp_id);
        let provider: *mut Object = msg_send![provider_cls, alloc];
        let provider: *mut Object = msg_send![provider, initWithRelyingPartyIdentifier: rp_ns];

        // ── 3. Build request object ──────────────────────────────────────────────────────────────
        let challenge   = NSData::with_bytes(&opts.challenge);
        let user_id     = NSData::with_bytes(&opts.user.id);
        let user_name   = NSString::from_str(&opts.user.name);

        let request: *mut Object = msg_send![provider,
            createCredentialRegistrationRequestWithChallenge: challenge
            name: user_name
            userID: user_id
        ];

        // Optional display name (skip if empty to avoid invalid selector call)
        if !opts.user.display_name.is_empty() {
            let display = NSString::from_str(&opts.user.display_name);
            let _: () = msg_send![request, setDisplayName: display];
        }

        // Map user‑verification preference, if present
        if let Some(sel) = opts.authenticator_selection.as_ref().and_then(|s| s.user_verification.as_ref()) {
            let choice = match sel.as_str() {
                "required" => "required",
                "discouraged" => "discouraged",
                _ => "preferred",
            };
            let choice_ns = NSString::from_str(choice);
            let _: () = msg_send![request, setUserVerificationPreference: choice_ns];
        }

        // ── 4. Perform the authorization (mocked) ────────────────────────────────────────────────
        let credential = perform_authorization_request(vec![request])?;
        parse_attestation_result(credential)
    }
}

fn get_credential_inner(opts: PublicKeyCredentialRequestOptions) -> Result<PublicKeyCredential> {
    unsafe {
        // ── 1. Availability check ────────────────────────────────────────────────────────────────
        let provider_cls = Class::get("ASAuthorizationPlatformPublicKeyCredentialProvider").ok_or_else(||
            Error::new(Status::GenericFailure, "ASAuthorizationPlatformPublicKeyCredentialProvider not available (needs macOS 13+)")
        )?;

        // ── 2. Build provider ────────────────────────────────────────────────────────────────────
        let rp_id = opts.rp_id.as_deref().ok_or_else(|| Error::new(Status::InvalidArg, "RP ID is required"))?;
        let rp_ns  = NSString::from_str(rp_id);
        let provider: *mut Object = msg_send![provider_cls, alloc];
        let provider: *mut Object = msg_send![provider, initWithRelyingPartyIdentifier: rp_ns];

        // ── 3. Build request object ──────────────────────────────────────────────────────────────
        let challenge = NSData::with_bytes(&opts.challenge);
        let request: *mut Object = msg_send![provider, createCredentialAssertionRequestWithChallenge: challenge];

        // Map user‑verification preference, if present
        if let Some(pref) = opts.user_verification.as_ref() {
            let pref_ns = NSString::from_str(match pref.as_str() {
                "required" => "required",
                "discouraged" => "discouraged",
                _ => "preferred",
            });
            let _: () = msg_send![request, setUserVerificationPreference: pref_ns];
        }

        // TODO: allow_credentials → NSArray<NSData *> (skipped for now)

        // ── 4. Perform the authorization (mocked) ────────────────────────────────────────────────
        let credential = perform_authorization_request(vec![request])?;
        parse_assertion_result(credential)
    }
}

// -------------------------------------------------------------------------------------------------
//  Minimal stand‑in for an ASAuthorizationController round‑trip.
//  Replace with real async delegate when integrating with UI.
// -------------------------------------------------------------------------------------------------

unsafe fn perform_authorization_request(_requests: Vec<*mut Object>) -> Result<*mut Object> {
    // Basic runtime version gate (major >= 13)
    let proc_cls = Class::get("NSProcessInfo").unwrap();
    let proc: *mut Object = msg_send![proc_cls, processInfo];
    let version: *mut Object = msg_send![proc, operatingSystemVersion];
    let major: i64 = msg_send![version, majorVersion];
    if major < 13 {
        return Err(Error::new(Status::GenericFailure, "macOS 13 (Ventura) or later required"));
    }

    // Mock success path – create a dummy NSObject so downstream code can
    // pretend it received an ASAuthorization credential.
    let nsobj_cls = Class::get("NSObject").unwrap();
    let obj: *mut Object = msg_send![nsobj_cls, new];
    Ok(obj)
}

// -------------------------------------------------------------------------------------------------
//  Result parsing helpers (mock data)
// -------------------------------------------------------------------------------------------------

unsafe fn parse_attestation_result(_credential: *mut Object) -> Result<PublicKeyCredential> {
    // Mock credential‑id bytes (16 random bytes)
    let cred_id_bytes: [u8; 16] = [
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    ];

    let client_data_json = b"{\"type\":\"webauthn.create\",\"challenge\":\"mock\",\"origin\":\"https://example.com\"}".to_vec();
    let att_object       = vec![0xA3, 0x63, 0x66, 0x6D, 0x74, 0x64]; // undersized CBOR – ok for mock

    let att_response = AuthenticatorAttestationResponse {
        client_data_json: Buffer::from(client_data_json),
        attestation_object: Buffer::from(att_object),
        transports: vec!["internal".to_string()],
    };

    Ok(PublicKeyCredential {
        id: base64_url_encode(&cred_id_bytes),
        raw_id: Buffer::from(&cred_id_bytes[..]),
        response: Either::A(att_response),
        authenticator_attachment: Some("platform".to_string()),
        type_: "public-key".to_string(),
    })
}

unsafe fn parse_assertion_result(_credential: *mut Object) -> Result<PublicKeyCredential> {
    let cred_id_bytes: [u8; 16] = [
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    ];

    let client_data_json = b"{\"type\":\"webauthn.get\",\"challenge\":\"mock\",\"origin\":\"https://example.com\"}".to_vec();
    let auth_data        = vec![0x49, 0x96, 0x0D, 0xE5];
    let signature        = vec![0x30, 0x45, 0x02, 0x20];

    let assert_response = AuthenticatorAssertionResponse {
        client_data_json: Buffer::from(client_data_json),
        authenticator_data: Buffer::from(auth_data),
        signature: Buffer::from(signature),
        user_handle: None,
    };

    Ok(PublicKeyCredential {
        id: base64_url_encode(&cred_id_bytes),
        raw_id: Buffer::from(&cred_id_bytes[..]),
        response: Either::B(assert_response),
        authenticator_attachment: Some("platform".to_string()),
        type_: "public-key".to_string(),
    })
}

// -------------------------------------------------------------------------------------------------
//  Utility helpers
// -------------------------------------------------------------------------------------------------

fn base64_url_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}
