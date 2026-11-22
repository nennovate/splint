//! What an owner is shown to approve a kind for a contact, which a kind with currency needs before
//! their agent uses it (Nenye, 2026-11-15): its fields in core's fixed words, and, where its name is an
//! example's or another agreed kind's, that it's the contact's own kind, with the start of each
//! fingerprint. Two agents agree a kind with no owner asked, and the other agent may have written it,
//! so a name alone says nothing of what it holds. Every device that asks an owner to
//! approve one shows this, so the same kind reads the same everywhere. Core knows no kind, the examples
//! included, so the owner's side passes in the examples it ships. Provisional, for Nenye.

use serde::{Deserialize, Serialize};

use super::{InteractionType, Schema, Schemas};

/// Whose a kind of a known name is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SameName {
    /// Exactly the example Splint ships of that name.
    TheExample,
    /// The contact's own, named like an example.
    LikeAnExample,
    /// The contact's own, named like a kind agreed with someone else.
    LikeAnotherAgreed,
}

/// One kind as an owner is asked to approve it.
/// Read back only by a terminal from Splint on the same computer, which worked it out.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KindForApproval {
    #[serde(rename = "type")]
    pub interaction: InteractionType,
    /// Its name and version.
    pub name: String,
    pub fingerprint: String,
    pub includes_currency: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub same_name: Option<SameName>,
    /// Every line a person is shown, in order: what it is, then each field.
    pub lines: Vec<String>,
}

/// How `schema`, agreed with a contact, is shown to its owner for approval. `examples` are the ones
/// Splint ships, and `others` the IDs of the other kinds this owner's side holds agreed, with anyone,
/// which a lookalike would be named after.
pub fn for_approval<'a>(
    schema: &Schema,
    examples: &Schemas,
    others: impl IntoIterator<Item = &'a InteractionType>,
) -> KindForApproval {
    let id = schema.name();
    let name = id.name().to_owned();
    let fingerprint = id.short_fingerprint().unwrap_or_default();
    let example = examples.named(&name);
    let other = others
        .into_iter()
        .find(|other| other.name() == name && *other != id);
    let (same_name, first) = match (example, other) {
        (Some(example), _) if example.name() == id => (
            Some(SameName::TheExample),
            format!("{name}, fingerprint {fingerprint}: the same as the example Splint ships."),
        ),
        (Some(example), _) => (
            Some(SameName::LikeAnExample),
            format!(
                "{name}, fingerprint {fingerprint}: their own kind, not the example Splint ships, \
                 whose fingerprint is {}.",
                example.name().short_fingerprint().unwrap_or_default()
            ),
        ),
        (None, Some(other)) => (
            Some(SameName::LikeAnotherAgreed),
            format!(
                "{name}, fingerprint {fingerprint}: their own kind, not the {name} agreed with \
                 someone else, whose fingerprint is {}.",
                other.short_fingerprint().unwrap_or_default()
            ),
        ),
        (None, None) => (None, format!("{name}, fingerprint {fingerprint}.")),
    };
    let mut lines = vec![first];
    lines.extend(schema.described());
    let includes_currency = schema.includes_currency();
    if includes_currency {
        lines.push(
            "It has money, so your agent uses it only once you approve it. Then a price you'd pay in it \
             always waits for you, and one your agent quotes follows your setting for quotes."
                .to_owned(),
        );
    }
    KindForApproval {
        interaction: id.clone(),
        name,
        fingerprint,
        includes_currency,
        same_name,
        lines,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bug caught: a contact's own kind named like an example read as the example when the
    /// owner was asked to approve it, so a lookalike with a price labelled as theirs passed for it.
    #[test]
    fn a_lookalike_is_named_as_the_contacts_own_with_both_fingerprints() {
        let examples = crate::requests::examples();
        let example = examples.named("quote/1").unwrap().clone();
        let mut document = serde_json::to_value(example.as_ref()).unwrap();
        document["paid"]["amount_minor"] = "requester".into();
        let lookalike = Schema::parse(document.to_string().as_bytes()).unwrap();
        let shown = for_approval(&lookalike, &examples, []);
        assert_eq!(shown.same_name, Some(SameName::LikeAnExample));
        let theirs = lookalike.name().short_fingerprint().unwrap();
        let ours = example.name().short_fingerprint().unwrap();
        assert_ne!(theirs, ours);
        assert!(shown.lines[0].contains(&theirs) && shown.lines[0].contains(&ours));
        assert!(shown.includes_currency);
        // Each field is shown, the money with the side it's paid to.
        assert!(
            shown.lines.iter().any(|line| line.contains("amount_minor")
                && line.contains("money paid to whoever opens it"))
        );
        assert!(
            shown
                .lines
                .iter()
                .any(|line| line.contains("quantity") && line.contains("not labelled as money"))
        );
        // The example itself says so, and a lookalike of another agreed kind says whose.
        assert_eq!(
            for_approval(&example, &examples, []).same_name,
            Some(SameName::TheExample)
        );
        let mut renamed = document.clone();
        renamed["type"] = "haircut/1".into();
        let theirs = Schema::parse(renamed.to_string().as_bytes()).unwrap();
        renamed["paid"]["amount_minor"] = "recipient".into();
        let agreed_elsewhere = Schema::parse(renamed.to_string().as_bytes()).unwrap();
        assert_eq!(
            for_approval(&theirs, &examples, [agreed_elsewhere.name()]).same_name,
            Some(SameName::LikeAnotherAgreed)
        );
        assert_eq!(
            for_approval(&theirs, &examples, []).same_name,
            None,
            "control"
        );
    }
}
