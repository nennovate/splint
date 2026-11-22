//! One of the two files allowed `unsafe`, approved by Nenye on 2026-11-14 for the Mac's security
//! chip: the two calls that cross from Rust's Core Foundation types to the Objective-C ones Apple
//! offers no safe way to reach. Nothing here touches key material: one reads the chip's handle for a
//! key out of the attributes it gives back, and one makes the context that carries the words of the
//! Touch ID prompt.
#![allow(unsafe_code)]

use core_foundation::base::{CFType, TCFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use objc2_foundation::NSString;
use objc2_local_authentication::LAContext;
use security_framework::key::SecKey;

/// The attribute that holds the chip's handle for a key, `kSecAttrTokenOID`.
const TOKEN_OBJECT: &str = "toid";

/// The handle the chip gave for `key`, which only this chip can use, as the bytes to keep in a file.
pub fn token_object(key: &SecKey) -> Option<Vec<u8>> {
    let attributes = key.attributes();
    // SAFETY: `SecKeyCopyAttributes` gives a dictionary keyed by `CFString`s with `CFType` values,
    // and `attributes` keeps it alive while the typed view borrows it under the get rule.
    let typed: CFDictionary<CFString, CFType> =
        unsafe { CFDictionary::wrap_under_get_rule(attributes.as_concrete_TypeRef()) };
    let found = typed.find(CFString::from_static_string(TOKEN_OBJECT))?;
    Some(found.downcast::<CFData>()?.bytes().to_vec())
}

/// A fresh authentication context whose prompt says `reason`, as a `CFType` for the key's attributes.
/// One context authenticates once, so every signature this run makes with it shares one prompt.
pub fn prompt_context(reason: &str) -> CFType {
    // SAFETY: `+[LAContext new]` and `-setLocalizedReason:` have no preconditions, and the string
    // outlives the call. An `LAContext` is toll-free a `CFTypeRef`, and wrapping it under the get
    // rule retains it, so the `CFType` keeps it alive after `context` is dropped here.
    unsafe {
        let context = LAContext::new();
        context.setLocalizedReason(&NSString::from_str(reason));
        CFType::wrap_under_get_rule(objc2::rc::Retained::as_ptr(&context).cast())
    }
}
