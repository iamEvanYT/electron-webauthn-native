use napi::bindgen_prelude::Buffer;

#[cfg(target_os = "macos")]
use {
    std::{slice},
    tokio::sync::oneshot,
    anyhow::{anyhow, Result},
    objc::{
        class, declare::ClassDecl, msg_send, sel, sel_impl,
        runtime::{Object, Protocol, Sel},
    },
    objc_foundation::{
        INSArray, INSString, NSArray, NSData, NSString,
    },
    base64::engine::{general_purpose::STANDARD as B64, Engine},
    napi::{Error, Status},
};
use crate::{
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions, 
    PublicKeyCredential
};

/// macOS passkey / WebAuthn assertion
pub async fn get_credential_impl(
    opts: PublicKeyCredentialRequestOptions,
) -> Result<PublicKeyCredential> {
    // --- Convert high‑level Rust values to Cocoa/Foundation types -----------------------------
    let rp_id = opts
        .rp_id
        .as_deref()
        .ok_or_else(|| anyhow!("`rp_id` is required on macOS"))?;
    let rp_id_ns = NSString::from_str(rp_id);

    let challenge_ns = unsafe { NSData::from_bytes(&opts.challenge) };

    // Provider & request ----------------------------------------------------------------------
    let provider: *mut Object = unsafe {
        let cls = class!(ASAuthorizationPlatformPublicKeyCredentialProvider);
        msg_send![cls, alloc]
    };
    let provider: *mut Object =
        unsafe { msg_send![provider, initWithRelyingPartyIdentifier: rp_id_ns] };

    let request: *mut Object = unsafe {
        msg_send![provider, createCredentialAssertionRequestWithChallenge: challenge_ns]
    };

    // Allowed credentials ---------------------------------------------------------------------
    if let Some(list) = &opts.allow_credentials {
        let mut objc_descs: Vec<*mut Object> = Vec::with_capacity(list.len());
        for cred in list {
            let data = unsafe { NSData::from_bytes(&cred.id) };
            let desc_cls = class!(ASAuthorizationPublicKeyCredentialDescriptor);
            let desc: *mut Object = unsafe { msg_send![desc_cls, alloc] };
            let desc: *mut Object =
                unsafe { msg_send![desc, initWithCredentialID:data transports:nil] };
            objc_descs.push(desc);
        }
        let nsarray = NSArray::from_vec(objc_descs);
        unsafe { let _: () = msg_send![request, setAllowedCredentials: nsarray]; }
    }

    // Channel to bridge Obj‑C delegate ↔ Rust async -------------------------------------------
    let (tx, rx) = oneshot::channel::<Result<PublicKeyCredential>>();

    // -----------------------------------------------------------------------------------------
    // Build an Objective‑C delegate class at run‑time whose sole job is to forward
    // ASAuthorizationControllerDelegate callbacks into the Rust `oneshot::Sender`.
    // -----------------------------------------------------------------------------------------
    unsafe {
        static mut DELEGATE_ONCE: std::sync::Once = std::sync::Once::new();
        DELEGATE_ONCE.call_once(|| {
            let superclass = class!(NSObject);
            let mut decl = ClassDecl::new("RustPasskeyDelegate", superclass).unwrap();

            // Store the Sender pointer inside the delegate instance
            decl.add_ivar::<*mut oneshot::Sender<Result<PublicKeyCredential>>>("tx");

            extern "C" fn did_complete(
                this: &mut Object,
                _: Sel,
                _: *mut Object,          /* controller */
                authorization: *mut Object,
            ) {
                unsafe {
                    // Extract credential ------------------------------------------------------
                    let credential: *mut Object = msg_send![authorization, credential];
                    let raw_id_ns: *mut Object = msg_send![credential, credentialID];

                    let len: usize = msg_send![raw_id_ns, length];
                    let bytes: *const u8 = msg_send![raw_id_ns, bytes];
                    let raw = slice::from_raw_parts(bytes, len).to_vec();

                    // Build PublicKeyCredential ----------------------------------------------
                    let result = PublicKeyCredential {
                        id: B64.encode(&raw),
                        raw_id: raw.into(),
                        // The authenticatorData / clientDataJSON / sig are not part of this
                        // simplified example. Extend here if you need the full response.
                        response: Buffer::from(Vec::new()),
                        authenticator_attachment: None,
                        type_: "public-key".to_string(),
                    };

                    // Send to waiting future -------------------------------------------------
                    let tx_ptr: *mut oneshot::Sender<Result<PublicKeyCredential>> =
                        *this.get_ivar("tx");
                    if let Some(tx) = tx_ptr.as_mut() {
                        let _ = tx.send(Ok(result));
                    }
                }
            }

            extern "C" fn did_error(
                this: &mut Object,
                _: Sel,
                _: *mut Object, /* controller */
                error: *mut Object,
            ) {
                unsafe {
                    let code: i64 = msg_send![error, code];
                    let desc_ns: *mut Object = msg_send![error, localizedDescription];
                    let desc = NSString::from_ptr(desc_ns).as_str().to_owned();

                    let tx_ptr: *mut oneshot::Sender<Result<PublicKeyCredential>> =
                        *this.get_ivar("tx");
                    if let Some(tx) = tx_ptr.as_mut() {
                        let _ =
                            tx.send(Err(anyhow!("ASAuthorization error {}: {}", code, desc)));
                    }
                }
            }

            decl.add_method(
                sel!(authorizationController:didCompleteWithAuthorization:),
                did_complete as extern "C" fn(&mut Object, Sel, *mut Object, *mut Object),
            );
            decl.add_method(
                sel!(authorizationController:didCompleteWithError:),
                did_error as extern "C" fn(&mut Object, Sel, *mut Object, *mut Object),
            );

            // Adopt the official protocol
            decl.add_protocol(&Protocol::get("ASAuthorizationControllerDelegate").unwrap());

            decl.register();
        });

        // Instantiate delegate and stash the Sender inside it ---------------------------------
        let delegate_cls = class!(RustPasskeyDelegate);
        let delegate: *mut Object = msg_send![delegate_cls, alloc];
        let delegate: *mut Object = msg_send![delegate, init];
        (*delegate).set_ivar("tx", Box::into_raw(Box::new(tx)));

        // Build controller --------------------------------------------------------------------
        let requests = NSArray::from_vec(vec![request]);
        let controller_cls = class!(ASAuthorizationController);
        let controller: *mut Object = msg_send![controller_cls, alloc];
        let controller: *mut Object =
            msg_send![controller, initWithAuthorizationRequests: requests];
        let _: () = msg_send![controller, setDelegate: delegate];

        // Kick off the authorization flow (UI will appear) ------------------------------------
        let _: () = msg_send![controller, performRequests];
    }

    // Convert the delegate callback into an async `Result`.
    rx.await.map_err(|_| anyhow!("credential flow cancelled or failed"))
}

pub async fn create_credential_impl(_options: PublicKeyCredentialCreationOptions) -> Result<PublicKeyCredential> {
    Err(Error::new(
        Status::GenericFailure,
        "Create credential is not supported on this platform"
    ))
}

pub async fn is_supported_impl() -> Result<bool> {
    Ok(true)
}