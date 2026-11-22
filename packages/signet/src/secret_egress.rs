//! Gate 4's ceiling on this agent's own secrets: words it writes never carry its tokens or private keys,
//! its owner's private keys or a backup key, or a Splint pairing or recovery code, whoever asked for
//! them. It's checked before anything is signed, counted or sent, and holds with a fully fooled agent.
//! See "An agent's own secrets" in `docs/protocol.md`.

use serde::Serialize;
use splint_core::delegation::DelegateKey;
use splint_core::requests::{Action, FieldValue, Fields};
use splint_core::secrets_in_text::{MAX_SCANNED_BYTES, OwnSecrets, SecretKind};

use crate::Signet;
use crate::agent_api::ApiError;
use crate::host_client::HostError;

/// Said of text no envelope could carry, which is refused before anything looks at it.
const TOO_LONG: &str =
    "too_long: that's longer than any envelope carries, so nothing was signed or sent";

/// Refuses `text` if it holds a secret. It names only the kind, so nothing of the text goes back,
/// and nothing of it is logged. Text longer than any envelope is refused unread, and the look itself
/// runs off the threads that answer calls, so a fooled agent's long text holds up nothing else.
pub async fn refuse_secrets(signet: &Signet, text: &str) -> Result<(), ApiError> {
    if text.is_empty() {
        return Ok(());
    }
    if text.len() > MAX_SCANNED_BYTES {
        return Err(ApiError::BadRequest(TOO_LONG));
    }
    let secrets = own_secrets(signet)?;
    let text = text.to_owned();
    let found = tokio::task::spawn_blocking(move || secrets.found_in(&text))
        .await
        .map_err(|_| HostError::LocalStorage)?;
    match found {
        Some(kind) => Err(ApiError::HoldsSecret(kind)),
        None => Ok(()),
    }
}

/// What Signet holds that this agent could be fooled into writing out, and the keys it doesn't hold but
/// knows by their public halves: its owner's, and the backups its owner's and its own IDs commit to,
/// whose files can sit beside the agent. The delegate key is read from its file each time, as it can
/// be replaced while Signet runs, and not under its lock, which a pass for the owner holds across calls
/// to the host: words going out never wait on those.
fn own_secrets(signet: &Signet) -> Result<OwnSecrets, ApiError> {
    let mut secrets = OwnSecrets::default();
    secrets.token(&signet.api_token);
    if let Some(owner_token) = &signet.requests.owner_token {
        secrets.token(owner_token);
    }
    secrets.signing_key(&signet.key)?;
    secrets.sealing_key(&signet.seal_key)?;
    let delegate =
        DelegateKey::load(signet.delegation.key_file()).map_err(|_| HostError::LocalStorage)?;
    secrets.delegate_key(&delegate)?;
    let who = signet.who();
    secrets.private_keys_of(&who.owner);
    secrets.private_keys_of(&who.identity);
    Ok(secrets)
}

/// Every word a move carries, a line to each field, so a secret split across two fields is still found
/// where line breaks are looked past. A move with none, such as an owner's `confirm`, gives the empty
/// string.
pub fn words_of(action: &Action) -> String {
    match action {
        Action::Say { fields }
        | Action::Counter { terms: fields }
        | Action::Accept { pick: fields }
        | Action::Deliver { result: fields } => words_in(fields),
        Action::Clarify { reason }
        | Action::Progress { status: reason }
        | Action::Decline { reason } => reason.as_str().to_owned(),
        _ => String::new(),
    }
}

/// The text values in a step's fields, in their one order, a line each. A field is its own word, so a key
/// sent as one isn't glued to the words of the fields beside it, which would hide an owner's key: those
/// are known only by their public halves and tried where a word's runs start and end.
pub fn words_in(fields: &Fields) -> String {
    let texts: Vec<&str> = fields
        .values()
        .filter_map(|value| match value {
            FieldValue::Text(text) => Some(text.as_str()),
            FieldValue::Int(_) | FieldValue::Times(_) => None,
        })
        .collect();
    texts.join("\n")
}

#[derive(Serialize)]
pub struct HoldsSecretBody {
    /// Starts with the kind, `holds_secret`, so a caller that shows only this still says what happened.
    error: String,
    secret: SecretKind,
}

/// The fixed words an agent hears: what kind of secret, and that nothing went.
pub fn refusal(kind: SecretKind) -> HoldsSecretBody {
    HoldsSecretBody {
        error: format!(
            "holds_secret: what you wrote holds {}, so nothing was signed or sent. Signet never \
             sends an agent's own token or keys, its owner's keys or backup keys, or a Splint \
             pairing or recovery code, whoever asks for them.",
            kind.described()
        ),
        secret: kind,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::sealing::tests::signet_and_owner;

    /// Where a P-256 key's private scalar starts in the PKCS#8 a key file holds.
    const SCALAR_STARTS_AFTER: [u8; 5] = [0x02, 0x01, 0x01, 0x04, 0x20];
    const SCALAR_BYTES: usize = 32;

    /// A key file's scalar in hex, read from it, as an agent on the same account could.
    fn scalar_in_hex(file: &std::path::Path) -> String {
        let pkcs8 = std::fs::read(file).unwrap();
        let start = pkcs8
            .windows(SCALAR_STARTS_AFTER.len())
            .position(|window| window == SCALAR_STARTS_AFTER)
            .unwrap()
            + SCALAR_STARTS_AFTER.len();
        let scalar = pkcs8.get(start..start + SCALAR_BYTES).unwrap();
        scalar.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// Bug caught: every send, open and move waited on the delegation's lock, which a pass for the
    /// owner holds across calls to a host that may take seconds each, so an agent's words queued
    /// behind it and an adapter that gave up sent them twice.
    #[tokio::test]
    async fn words_going_out_never_wait_on_a_pass_for_the_owner() {
        let (signet, directory, _) = signet_and_owner(None, "egress-lock").await;
        let delegate = scalar_in_hex(&directory.join("delegate.key"));
        let pass = signet.delegation.held().await;
        let looked = tokio::time::timeout(Duration::from_secs(10), async {
            (
                refuse_secrets(&signet, "see you at noon").await,
                refuse_secrets(&signet, &format!("the key is {delegate}")).await,
            )
        })
        .await;
        drop(pass);
        let (ordinary, holding) = looked.unwrap();
        assert!(ordinary.is_ok());
        assert!(matches!(
            holding,
            Err(ApiError::HoldsSecret(SecretKind::PrivateKey))
        ));
    }

    /// Bug caught: a step's fields were run together with nothing between them, so an owner's key sent
    /// as one field was glued to the words of the fields beside it and went out, as Signet knows it only
    /// by its public half and tries only where a word's runs start and end, or near them.
    #[tokio::test]
    async fn an_owners_key_in_a_field_is_found_whatever_the_fields_beside_it_say() {
        let (signet, directory, owner_key) = signet_and_owner(None, "egress-fields").await;
        let file = directory.join("owner.key");
        owner_key.save_new(&file).unwrap();
        // Hex letters on both sides, longer than a word glued to a key can be and still be looked past.
        let fields = Fields::from([
            (
                "a".to_owned(),
                FieldValue::Text("note deadbeefcafefacade".to_owned()),
            ),
            ("b".to_owned(), FieldValue::Text(scalar_in_hex(&file))),
            ("c".to_owned(), FieldValue::Text("added".to_owned())),
        ]);
        assert!(matches!(
            refuse_secrets(&signet, &words_in(&fields)).await,
            Err(ApiError::HoldsSecret(SecretKind::OwnerKey))
        ));
    }
}
