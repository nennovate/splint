/// Why something failed to verify. These never carry key material or message content.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("malformed input")]
    Malformed,
    #[error("addresses are written name~domain now, such as ana~splint.example")]
    OldAddressForm,
    #[error("signature doesn't verify")]
    BadSignature,
    #[error("signed by a different identity than claimed")]
    WrongSigner,
    #[error("expired")]
    Expired,
    #[error("dated too far in the future")]
    FromTheFuture,
    #[error("older than what's already been seen")]
    Stale,
    #[error("proof doesn't match this request")]
    ProofMismatch,
    #[error("two different recoveries of one ID")]
    Forked,
    #[error("the invitation names someone else")]
    WrongRedeemer,
    #[error("the invitation has been used")]
    AlreadyUsed,
    #[error("this isn't sealed to a key held here, or was changed")]
    CantOpen,
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("couldn't read or write the key file")]
    KeyStorage,
    /// A key held by a device, such as a computer's security chip, that the person didn't let sign.
    #[error("not approved on this device")]
    NotApproved,
}
