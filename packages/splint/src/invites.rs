//! Invites, from the agent's machine: `splint invite`, `invites`, `accept`, `decline` and `card`. Each
//! is a call to this agent's Signet, which does the checking and the signing. A contact both agents
//! agreed to still needs the owner's side to sign them in: for an agent nobody has set up controls
//! for, that's its stand-in, here and in `splint auto`, and otherwise the owner, on their page.

use serde_json::{Value, json};
use splint_core::rules::RulesDraft;

use crate::contacts::with_contact;
use crate::failure::Failure;
use crate::home::{Home, Installed};
use crate::owner_key::OwnerKey;
use crate::owner_side::OwnerSide;
use crate::signet_api::SignetApi;

/// What a command says, in words for a person and as JSON for a program.
pub struct Said {
    pub text: String,
    pub json: Value,
}

/// A path segment an agent typed, which can't name another call.
fn one_segment(given: &str) -> Result<&str, Failure> {
    let fits = !given.is_empty()
        && given != "."
        && given != ".."
        && given.len() <= 300
        && given
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "~.-:[]_".contains(c));
    if fits {
        Ok(given)
    } else {
        Err(Failure::refused(
            "name an invite by the address it's from, or the start of its ID",
        ))
    }
}

/// A field of what Signet answered, or nothing.
fn words_at<'a>(answer: &'a Value, pointer: &str) -> &'a str {
    answer
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn list_at<'a>(answer: &'a Value, pointer: &str) -> impl Iterator<Item = &'a Value> {
    answer
        .pointer(pointer)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

pub async fn invite(home: &Home, to: &str) -> Result<Said, Failure> {
    let (installed, _) = Installed::require(home)?;
    let api = SignetApi::new(home, &installed)?;
    let sent = api.agent_post("/v0/invites", &json!({ "to": to })).await?;
    let to = words_at(&sent, "/to").to_owned();
    let after = if OwnerKey::new(home).is_stand_in() {
        "they become one of your contacts at once"
    } else {
        "they're your contact at once, unless your person's rules have them wait for your person"
    };
    Ok(Said {
        text: format!(
            "Invited {to}. If their agent accepts, {after}. Their agent sees only your address. \
             {} invites shows whether they have.",
            home.command()
        ),
        json: sent,
    })
}

/// Signs in what both agents agreed to, if this agent's owner is a stand-in on this machine. A real
/// owner's contacts are theirs to sign, on their page.
pub async fn sign_agreed(home: &Home, side: &OwnerSide) -> Result<usize, Failure> {
    let OwnerSide::Beside { installed, agent } = side else {
        return Ok(0);
    };
    if !OwnerKey::new(home).is_stand_in() {
        return Ok(0);
    }
    let own = (installed.address.as_str(), agent);
    let held = side.held(home).await?;
    // This runs every few seconds, so the rules in force are read only once there's something to sign.
    if add_agreed(&mut side.rules_kept_here(home)?.draft, own, &held, &[])? == 0 {
        return Ok(0);
    }
    let mut signed = side.rules(home).await?;
    let added = add_agreed(&mut signed.draft, own, &held, &[])?;
    if added > 0 {
        side.apply_rules(home, signed.draft).await?;
    }
    Ok(added)
}

/// Adds each contact whose invite and acceptance check out here, for this agent, by the signatures of
/// the two agents. What doesn't check out, or doesn't fit the rules, waits as it was.
fn add_agreed(
    draft: &mut RulesDraft,
    own: (&str, &splint_core::SplintId),
    held: &[crate::signet_api::Held],
    types: &[splint_core::requests::InteractionType],
) -> Result<usize, Failure> {
    let mut added = 0_usize;
    for one in held.iter().filter(|one| one.kind == "invite") {
        let Some(new) = one
            .invite
            .as_ref()
            .and_then(|record| record.verify(own.1).ok())
        else {
            continue;
        };
        if let Ok(true) = with_contact(draft, own, &new.address, new.agent, types.to_vec()) {
            added = added.saturating_add(1);
        }
    }
    Ok(added)
}

pub async fn invites(home: &Home) -> Result<Said, Failure> {
    let (installed, _) = Installed::require(home)?;
    if let Ok(side) = OwnerSide::resolve(home, None, "sign in contacts") {
        sign_agreed(home, &side).await?;
    }
    let api = SignetApi::new(home, &installed)?;
    let listed = api.agent_get("/v0/invites").await?;
    // As this agent, or a profile's answer would reach the default agent.
    let splint = home.command();
    let mut lines = Vec::new();
    for one in list_at(&listed, "/invites") {
        let says = words_at(one, "/says");
        let controls = one
            .pointer("/controls")
            .and_then(Value::as_str)
            .map(|words| format!(" Controls: {words}."))
            .unwrap_or_default();
        let from = words_at(one, "/from");
        let same = if one.pointer("/same_owner") == Some(&Value::Bool(true)) {
            " It acts for your person too."
        } else {
            ""
        };
        lines.push(format!(
            "  {says}.{controls}{same}\n    {splint} accept {from}, or {splint} decline {from}"
        ));
    }
    for one in list_at(&listed, "/sent") {
        let to = words_at(one, "/to");
        let state = if one
            .pointer("/accepted")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            "accepted"
        } else {
            "not answered yet"
        };
        lines.push(format!("  You invited {to}: {state}."));
    }
    for address in list_at(&listed, "/waiting_for_owner") {
        lines.push(format!(
            "  {} agreed, and waits for your owner to approve them on their page.",
            address.as_str().unwrap_or_default()
        ));
    }
    for one in list_at(&listed, "/held") {
        let address = words_at(one, "/address");
        lines.push(format!(
            "  {address} wrote to you, and it's held unread as they're not a contact. Nothing they \
             wrote is shown. {splint} invite {address} if your person would want to hear from them."
        ));
    }
    let text = if lines.is_empty() {
        format!(
            "No invites. {splint} invite HANDLE~HOST invites someone, and {splint} card prints your \
             card."
        )
    } else {
        lines.join("\n")
    };
    Ok(Said { text, json: listed })
}

pub async fn accept(home: &Home, which: &str) -> Result<Said, Failure> {
    let (installed, _) = Installed::require(home)?;
    let api = SignetApi::new(home, &installed)?;
    let path = format!("/v0/invites/{}/accept", one_segment(which)?);
    let accepted = api.agent_post(&path, &json!({})).await?;
    let contact = words_at(&accepted, "/contact").to_owned();
    let waiting = accepted
        .pointer("/waiting_for_owner")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    // The accept is made, so nothing after it fails the command, or an agent trying again is told
    // it isn't there. Only a stand-in here signs the contact in, and an owner elsewhere signs it on
    // their controls.
    let signed = match OwnerSide::resolve(home, None, "sign in contacts") {
        Ok(side) => sign_agreed(home, &side).await,
        Err(_) => Ok(0),
    };
    let same = accepted.pointer("/same_owner") == Some(&Value::Bool(true));
    let text = if let Err(failure) = &signed {
        format!(
            "Accepted. {contact} isn't signed in as your contact yet, as that failed here: \
             {failure}. {} invites signs them in when it runs.",
            home.command()
        )
    } else if signed.is_ok_and(|added| added > 0) {
        format!("Accepted. {contact} is one of your contacts now, and you can write to them.")
    } else if !waiting && same {
        format!(
            "Accepted. {contact} acts for your person too, and is one of your contacts now. What it \
             asks is your person's request passed on, to act on within your own rules."
        )
    } else if !waiting {
        format!(
            "Accepted. {contact} is one of your contacts now, added by you: your person hasn't \
             approved them. Talk and arrange things as you like, and ask your person before you share \
             their private details with them or commit them to anything."
        )
    } else {
        format!(
            "Accepted. {contact} becomes one of your contacts once your person approves them on \
             their controls."
        )
    };
    Ok(Said {
        text,
        json: accepted,
    })
}

pub async fn decline(home: &Home, which: &str) -> Result<Said, Failure> {
    let (installed, _) = Installed::require(home)?;
    let api = SignetApi::new(home, &installed)?;
    let path = format!("/v0/invites/{}/decline", one_segment(which)?);
    let declined = api.agent_post(&path, &json!({})).await?;
    Ok(Said {
        text: "Declined. They aren't told.".to_owned(),
        json: declined,
    })
}

pub async fn card(home: &Home) -> Result<Said, Failure> {
    let (installed, _) = Installed::require(home)?;
    let api = SignetApi::new(home, &installed)?;
    let card = api.agent_get("/v0/card").await?;
    let text = format!(
        "Your contact card. Whoever has it can invite you with splint invite and the card, and it \
         needs no host to say who you are. Nothing in it is secret.\n\n  {}",
        words_at(&card, "/card")
    );
    Ok(Said { text, json: card })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_names_an_invite_cant_name_another_call() {
        for fine in ["ana~host.example", "ana.jo~[::1]:7001", "0123abcd"] {
            assert!(one_segment(fine).is_ok(), "{fine}");
        }
        for bad in ["../owner/rules", "a/b", "a?b", "a b", "", "a#b", ".."] {
            assert!(one_segment(bad).is_err(), "{bad}");
        }
    }
}
