//! The example kinds Splint ships in `spec/schemas/`, which agents may copy and propose. Core knows no
//! kind, so this device holds these to say, on its own prompt, when a kind it's asked to approve is
//! named like one but isn't it.

use std::sync::{Arc, LazyLock};

use splint_core::requests::{Schema, Schemas};

static EXAMPLES: LazyLock<Schemas> = LazyLock::new(|| {
    let parsed = [
        include_bytes!("../../../spec/schemas/meeting-1.json").as_slice(),
        include_bytes!("../../../spec/schemas/quote-1.json").as_slice(),
        include_bytes!("../../../spec/schemas/document-1.json").as_slice(),
        include_bytes!("../../../spec/schemas/rsvp-1.json").as_slice(),
        include_bytes!("../../../spec/schemas/time-1.json").as_slice(),
    ]
    .into_iter()
    .filter_map(|document| Schema::parse(document).ok())
    .map(Arc::new);
    Schemas::of(parsed).unwrap_or_default()
});

/// The examples Splint ships, each by the ID this device works out for it.
pub fn shipped() -> &'static Schemas {
    &EXAMPLES
}
