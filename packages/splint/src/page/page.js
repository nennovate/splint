// @ts-check
// The owner's page. Everything from a counterparty arrives as data and goes on the screen as text:
// this file only ever makes elements and sets their text, and never writes markup. It has no crypto
// and no key. It meets the program behind it over HTTP on this device, and nothing else.
"use strict";

const SESSION_KEY = "splint-owner-session";
const VIEW_KEY = "splint-owner-view";
const REFRESH_MILLIS = 4000;
const ARM_MILLIS = 5000;
// A redraw can move another decision under a click that was already on its way, and a counterparty
// can influence when one comes, so a signing button ignores clicks for this long after one.
const PAUSE_AFTER_REDRAW_MILLIS = 700;
const TOLD_MILLIS = 15000;
const AN_ID = /^splint1[0-9a-f]{64}$/;
// What Signet hands the page at most, besides what's waiting. state.rs says the same.
const MAX_EXCHANGES_SHOWN = 200;

/** @type {string | null} */
let secret = null;
// What Signet last handed the page, as parsed JSON.
/** @type {any} */
let state = null;
let lastText = "";
let lastRedraw = 0;
let toldTimer = 0;
// Unsaved settings, which a refresh mustn't overwrite.
/** @type {any} */
let edits = null;
// Whether contacts the agent added, which those settings would take out, stay as the owner's own:
// "keep" or "drop". Drop is chosen for the owner and shown before they sign, as keeping makes them the
// owner's own approved contacts, which only the owner's choice should do.
/** @type {"keep" | "drop" | null} */
let keepChoice = null;
// Who that choice was made for, so it doesn't carry over to others the page shows later.
let keepChoiceFor = "";
const typed = new Map();
const unrolled = new Set();
// Which view is open, and whether IDs show in the lists. Only how the page looks, never what's signed.
let view = "now";
let showIds = false;

// What's half typed into the form for a new link, which a refresh mustn't take away.
const linkForm = { type: "", days: 7, fields: new Map(), lastLink: "" };

const VIEWS = [
  ["now", "Now"],
  ["history", "History"],
  ["contacts", "Contacts"],
  ["links", "Links"],
  ["settings", "Settings"],
];

const STATES = {
  start: "Starting",
  talking: "Talking",
  offered: "Offered",
  clarifying: "Asked to clarify",
  accepted: "Agreed",
  working: "In progress",
  paused: "Paused",
  delivered: "Delivered",
  requester_confirmed: "One owner has signed",
  completed: "Completed",
  declined: "Declined",
  cancelled: "Cancelled",
  disputed: "Disputed",
  expired: "Expired",
};
const FINISHED = new Set(["completed", "declined", "cancelled", "disputed", "expired"]);
const STATE_DOTS = { completed: "good", disputed: "stop", paused: "warn", declined: "", cancelled: "", expired: "" };
// A line's own name says whose agent or person it is, and a person's line is marked by how it's drawn.
const ORIGINS = { owner: "Signed by an owner" };
const CHANGE_KINDS = {
  bound: "Acts for an owner",
  owner: "Has a new owner",
  key: "Replaced its key",
  signet: "Moved its Signet, or changed how its key is held",
  host: "Moved to a new host",
  revocation: "Its owner stopped it acting for them",
  declared: "Its owner declared a change",
};
const CHANGE_PROOFS = {
  signed: "Every signature checked.",
  unproven: "Unproven: its owner says so, and no device has attested to it.",
  unverified: "Unverified: its owner says so, and Splint can't see it.",
};
const STANDINGS = {
  ask: "Held until you say. Their messages wait on the host, and your agent can't write to them.",
  hold: "Held until you say. Their messages wait on the host, and your agent can't write to them.",
  waiting_for_history: "A new key or owner no history has explained yet. Their messages wait until one arrives.",
  rewritten: "Two histories part ways, which someone holding keys signed. It's held whatever your rules say.",
  continue: "Carrying on, as your rules say.",
};

// The link carries the secret after the #, which never leaves the browser. It's wiped from the
// address bar straight away, and kept only for this tab.
function takeSecret() {
  const found = new URLSearchParams(location.hash.slice(1)).get("s");
  if (found) {
    history.replaceState(null, "", location.pathname);
    try {
      sessionStorage.setItem(SESSION_KEY, found);
    } catch {
      // Private windows can refuse this. The secret stays in this variable until a reload.
    }
    return found;
  }
  try {
    return sessionStorage.getItem(SESSION_KEY);
  } catch {
    return null;
  }
}

async function call(path, body) {
  const response = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    headers: { Authorization: `Bearer ${secret}`, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const answer = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(answer.error || "That didn't work, so nothing changed.");
  }
  return answer;
}

// A quiet "Details" that holds what most owners never need: IDs, exact times, names as signed. It
// stays open across redraws.
function more(key, summary, ...kids) {
  const details = el("details", { class: "more", open: unrolled.has(key) },
    el("summary", {}, summary), el("div", { class: "more-body" }, ...kids));
  details.addEventListener("toggle", () => {
    if (details.open) {
      unrolled.add(key);
    } else {
      unrolled.delete(key);
    }
  });
  return details;
}


function dot(kind, live) {
  return el("span", { class: `dot ${kind || ""}${live ? " live" : ""}`, ariaHidden: "true" });
}

function tell(words, bad) {
  const told = /** @type {HTMLElement} */ (document.getElementById("told"));
  told.textContent = words;
  told.className = bad ? "bad" : "";
  told.hidden = !words;
  clearTimeout(toldTimer);
  if (words && !bad) {
    toldTimer = setTimeout(() => tell("", false), TOLD_MILLIS);
  }
}

async function act(button, path, body, afterwards) {
  button.disabled = true;
  try {
    const answer = await call(path, body);
    // A host that refused the owner's rules is said until the next thing is, not for a few seconds.
    tell(answer.said, Boolean(answer.host_refused));
    if (afterwards) afterwards();
    await refresh();
  } catch (failure) {
    tell(failure.message, true);
    button.disabled = false;
  }
}

function justRedrawn() {
  if (performance.now() - lastRedraw < PAUSE_AFTER_REDRAW_MILLIS) {
    tell("The page just changed, so that click didn't count. Look again.", true);
    return true;
  }
  return false;
}

// Two clicks, on a button that stays still, for anything that signs or can't be taken back. A redraw
// makes the button anew, so a click can't carry over onto something else.
function armedButton(label, armedLabel, kind, go) {
  let armed = false;
  const button = el("button", {
    type: "button",
    class: kind,
    onClick: () => {
      if (justRedrawn()) return;
      if (armed) {
        go(button);
        return;
      }
      armed = true;
      button.textContent = armedLabel;
      button.classList.add("armed");
      setTimeout(() => {
        armed = false;
        button.textContent = label;
        button.classList.remove("armed");
      }, ARM_MILLIS);
    },
  }, label);
  return button;
}

function field(...kids) {
  return el("div", { class: "field" }, ...kids);
}

// A text box whose explanation sits inside it until something's typed, so a card doesn't repeat it
// and nothing moves when it takes focus.
function typedInput(id, label, maxLength, help) {
  const input = el("input", {
    type: "text",
    id,
    maxLength,
    value: typed.get(id) || "",
    autocomplete: "off",
    placeholder: help || "",
    title: help || "",
  });
  input.addEventListener("input", () => typed.set(id, input.value));
  return [el("label", { htmlFor: id }, label), input];
}

function section(id, title, kids, options) {
  const { empty, aside, total } = options || {};
  if (kids.length === 0 && !empty) return null;
  return el("section", { id },
    title === null ? null : el("div", { class: "label" },
      el("h2", {}, title, total ? el("span", { class: "count" }, String(total)) : null),
      aside || null),
    ...(kids.length ? kids : [empty]));
}

function emptyState(title, words) {
  return el("div", { class: "empty" }, el("strong", {}, title), words ? el("p", { class: "small" }, words) : null);
}

function idsToggle() {
  return el("button", {
    type: "button",
    class: "link",
    onClick: () => {
      showIds = !showIds;
      render();
    },
  }, showIds ? "Hide IDs" : "Show IDs");
}

// Waiting for the owner -----------------------------------------------------------------------

// Opens Settings at the one that holds something for the owner.
function goToSetting(id) {
  openView("settings");
  const found = document.getElementById(id);
  if (!found) return;
  found.scrollIntoView({ block: "center" });
  found.focus({ preventScroll: true });
}

// Which of the owner's settings put this here, and a quiet way to change it.
function why(words, setting, after) {
  return el("p", { class: "why" }, words,
    setting
      ? el("span", {}, " ", el("button", { type: "button", class: "link", onClick: () => goToSetting(setting) }, "Change in Settings"), ` ${after}.`)
      : null);
}

function strangerCard(stranger) {
  const id = `stranger-${stranger.agent}`;
  const details = (...why) => more(`more-${id}`, "Details", exact(["ID", el("span", { class: "id" }, stranger.agent)]), ...why.map((words) => el("p", { class: "soft small" }, words)));
  if (stranger.disagreed) {
    return el("div", { class: "card", id },
      el("h3", {}, `The host of ${stranger.claims} names someone else there`),
      el("p", { class: "lead" }, "Its host gave another ID than the one you signed or your agent already knew there, so your agent won't take them for that contact. Check with them another way."),
      details("Either the host is lying or the address has changed hands."));
  }
  if (stranger.asked && !stranger.messages && !stranger.steps) {
    return el("div", { class: "card", id },
      el("h3", {}, `Your agent asks to write to ${stranger.claims}`),
      el("p", { class: "lead" }, "This is only your agent's word, and it may have been fooled into asking."),
      el("div", { class: "acts" },
        armedButton("Allow", "Click again to allow", "main", (button) =>
          act(button, "/api/let-in", { agent: stranger.agent })),
        armedButton("Block", "Click again to block", "stop", (button) =>
          act(button, "/api/block", { agent: stranger.agent }))),
      details("Adding them signs this ID. If that address's host answers with any other, nothing goes to them."));
  }
  const held = [
    stranger.messages ? count(stranger.messages, "message") : null,
    stranger.steps ? count(stranger.steps, "step") : null,
  ].filter(Boolean).join(" and ");
  return el("div", { class: "card", id },
    el("h3", {}, stranger.claims ? `Someone who says they're ${stranger.claims}` : "Someone who gave no address"),
    el("p", { class: "lead" }, `${held} held, the latest ${short(stranger.last_at)}. Your agent hasn't seen any of it.`),
    state.settings.reach.inbound.strangers === "quarantine"
      ? why("You asked to see anyone new first.", "reach-from", "to let later ones straight through")
      : null,
    el("div", { class: "acts" },
      stranger.claims
        ? armedButton("Let them in", "Click again to sign them in", "main", (button) =>
            act(button, "/api/let-in", { agent: stranger.agent }))
        : null,
      armedButton("Block", "Click again to block", "stop", (button) =>
        act(button, "/api/block", { agent: stranger.agent }))),
    details("Letting them in signs this ID, so a false address gets them nothing. What they sent isn't shown here."));
}

// A contact both agents agreed to by invite. The address and ID are what the two agents signed,
// checked on this device. Nothing either of them wrote is shown.
function inviteCard(invite) {
  const id = `invite-${invite.agent}`;
  const lead = invite.invited_by_us
    ? `Your agent invited ${invite.address}, and their agent accepted.`
    : `${invite.address} invited your agent, and your agent accepted.`;
  const until = invite.added_by_agent
    ? "Your agent added them by itself: they can already talk, and a kind with money, such as a quote, is used with them only once you approve it for them. Add them to approve them."
    : "They can't reach your agent until you say yes.";
  return el("div", { class: "card", id },
    el("h3", {}, invite.added_by_agent ? `Approve ${invite.address}?` : `Add ${invite.address} as a contact?`),
    el("p", { class: "lead" }, `${lead} ${until}`),
    el("div", { class: "acts" },
      armedButton("Add", "Click again to add them", "main", (button) =>
        act(button, "/api/let-in", { agent: invite.agent })),
      armedButton("Block", "Click again to block", "stop", (button) =>
        act(button, "/api/block", { agent: invite.agent }))),
    more(`more-${id}`, "Details", exact(["ID", el("span", { class: "id" }, invite.agent)]),
      el("p", { class: "soft small" }, "Adding them signs this ID, which their agent's own key signed for. If their host later names anyone else there, nothing goes to them.")));
}

// A kind with money the agent agreed with a contact, which it can't use until the owner approves it.
// Every line is core's fixed words around the names and words the kind's writer chose, worked out on
// this device from the schema, with whose kind it is where its name is an example's or another's.
function kindCard(waiting) {
  const kind = waiting.kind;
  const id = `kind-${waiting.agent}-${kind.fingerprint}`;
  const [first, ...rest] = kind.lines;
  return el("div", { class: "card", id },
    el("h3", {}, dot("accent"), el("span", {}, `Approve ${kind.name} with ${waiting.label}?`)),
    el("p", { class: kind.same_name && kind.same_name !== "the_example" ? "banner stop" : "lead" }, first),
    el("ul", { class: "soft small" }, ...rest.map((line) => el("li", {}, line))),
    el("div", { class: "acts" },
      armedButton("Approve", "Click again to approve it", "main", (button) =>
        act(button, "/api/approve-kind", { agent: waiting.agent, type: kind.type }))),
    more(`more-${id}`, "Details", exact(["Kind", el("span", { class: "id" }, kind.type)], ["Their agent", el("span", { class: "id" }, waiting.agent)])));
}

// A number its kind doesn't label as money never waits for the owner, so it's said where it's shown.
function numbersNotMoney(exchange) {
  const names = exchange.numbers_not_money || [];
  return names.length
    ? el("p", { class: "why" }, `A number not labelled as money: ${names.join(", ")}. It doesn't wait for you.`)
    : null;
}

// Another step waiting on the same exchange, as its own card says it.
const BESIDE = {
  confirm: "your yes to agree to it",
  cancel: "your agent's cancel",
  counter: "your agent's counter",
  accept: "your agent's accept",
  deliver: "your agent's delivery",
};

// Which of the owner's settings leaves this to them, from what the Rust side read in their rules.
function leftWords(toSign) {
  const left = toSign.left || {};
  const type = toSign.terms.type;
  switch (left.is) {
    case "ask_me":
      return ["You asked to approve these yourself.", "level"];
    case "commits_a_value":
      return ["This would commit you to an amount, such as a price you'd pay, so it waits for you at every level.", null];
    case "quoted_price":
      return ["A price your agent quotes, where you'd be the one paid, waits for you, as your settings say.", "quoted-prices"];
    case "asked_at_ask_me":
      return ["Your agent asked you about this while you had Ask me first, so it waits for your answer.", null];
    case "not_approved":
      return ["Your agent added them by itself, and you haven't approved them, so anything with money in it waits for you.", null];
    case "unapproved_contact":
      return ["You haven't approved them as a contact, so your delegate leaves anything with them to you.", null];
    case "not_a_confirm":
      return ["At Go ahead, your device signs by itself only the final yes on a kind you sign, so this waits for you.", "level"];
    case "unknown_type":
      return [`${typeName(type)} isn't installed here, so nothing approves it by itself.`, null];
    default:
      return [toSign.operation === "confirm"
        ? `${typeName(type)} needs your signature. Your settings let your device give it, and it hasn't yet.`
        : "Your settings let your device approve this, and it hasn't yet.", null];
  }
}

// One card for each draft waiting on an exchange: each is its own yes, to its own exact terms. Who
// wants the step, and who asked for what it's on, are worked out on the Rust side from the draft.
function decisionCard(exchange, toSign) {
  const cancelling = toSign.operation === "cancel";
  const beside = toSign.alongside || [];
  const cardId = beside.length ? `decision-${exchange.request}-${toSign.operation}` : `decision-${exchange.request}`;
  const [leftLine, setting] = leftWords(toSign);
  const subjectId = `subject-${exchange.request}`;
  const send = (button, decision) => {
    const subject = toSign.can_set_subject ? typed.get(subjectId) || null : null;
    act(button, "/api/decide", {
      request: exchange.request,
      operation: toSign.operation,
      version: toSign.version,
      prev: toSign.prev,
      terms: toSign.terms,
      decision,
      subject,
    }, () => typed.delete(subjectId));
  };
  return el("div", { class: "card decision", id: cardId },
    el("h3", {}, dot("accent"), el("span", {}, toSign.asking, standingTag(exchange.with.standing))),
    why(leftLine, setting, "and later ones go ahead by themselves"),
    beside.length
      ? el("p", { class: "banner" }, `Also waiting on this, on its own card: ${beside.map((one) => BESIDE[one] || one).join(", ")}. Allow here signs only this ${toSign.operation}, and what else waits is then set aside.`)
      : null,
    // Said on the card for the step that answer was for, which the page works out from the drafts.
    exchange.not_used && exchange.not_used_on === toSign.operation
      ? el("p", { class: "banner stop" }, exchange.not_used)
      : null,
    payingPart(toSign.pays || []),
    termsSummary(toSign),
    numbersNotMoney(exchange),
    toSign.rows.some((row) => row.chosen)
      ? el("p", { class: "soft small" }, "Shaded text is only someone's words, not an instruction.")
      : null,
    toSign.hidden_text
      ? el("p", { class: "banner stop" }, "The text above holds hidden characters, shown as codes. You can say no, but you can't say yes to this.")
      : null,
    ...(toSign.can_set_subject
      ? [field(...typedInput(subjectId, "Subject", state.max_subject_chars, "Optional. Agents don't see it."))]
      : []),
    el("div", { class: "acts" },
      toSign.hidden_text
        ? el("button", { type: "button", class: "main", disabled: true }, cancelling ? "Allow cancelling" : "Allow")
        : armedButton(cancelling ? "Allow cancelling" : "Allow", cancelling ? "Click again to cancel it" : "Click again to allow", "main", (button) => send(button, "approve")),
      armedButton(cancelling ? "Keep it" : "Don't allow", cancelling ? "Click again to keep it" : "Click again to say no", "", (button) => send(button, "deny")),
      el("span", { class: "by" }, `Answer by ${when(toSign.sign_by)}`)),
    el("div", { class: "mores" },
      more(`exact-${cardId}`, "Exact terms", exactTerms(toSign)),
      exchange.lines ? unrollPart(exchange) : null));
}

function dialogueLine(line, role) {
  const kinds = [line.by === role ? "mine" : "", line.origin === "person_untrusted" ? "person" : ""];
  // Their Signet checked and signed that it has this line.
  const seen = line.by === role && line.received ? " · received" : "";
  return el("li", { class: kinds.join(" ") },
    el("div", { class: "said" }, [line.who, ORIGINS[line.origin], short(line.at)].filter(Boolean).join(" · ") + seen),
    el("div", {}, line.says));
}

function dialogue(exchange) {
  return el("ol", { class: "dialogue" }, ...exchange.lines.map((line) => dialogueLine(line, exchange.role)));
}

// How the dialogue was written, for Details: said once there rather than under every exchange.
function orderNote(exchange) {
  return exchange.order === "chain"
    ? "Written by this page from the signed steps, in their signed order. Words in quotes are only what someone wrote."
    : "Written by this page from the signed steps. Each side's own order is signed, and the order between them is only each signer's date. Words in quotes are only what someone wrote.";
}

function unrollPart(exchange) {
  return more(`unroll-${exchange.request}`, "Read the whole exchange",
    dialogue(exchange),
    el("p", { class: "foot-note" }, orderNote(exchange)));
}

function changeLines(changes, label) {
  return el("div", {},
    label ? el("p", { class: "soft small" }, label) : null,
    ...changes.map((change) =>
      el("p", {},
        `${CHANGE_KINDS[change.kind] || change.kind}, ${short(change.issued_at)}. ${CHANGE_PROOFS[change.proof] || ""}`,
        change.claim
          ? el("span", { class: "soft" }, ` Their owner's words: "${change.claim.what || `${change.claim.location}, ${change.claim.protection}`}"`)
          : null)));
}

function noticeCard(notice) {
  const accept = (head, label, armedLabel) =>
    armedButton(label, armedLabel, "main", (button) =>
      act(button, "/api/accept-change", { contact: notice.contact, head }));
  const buttons = [];
  if (notice.standing === "rewritten") {
    if (notice.rewritten_head) {
      buttons.push(accept(notice.rewritten_head, "Go with the new history", "Click again to sign the new history"));
    }
    buttons.push(accept(notice.head, "Stay with what you've seen", "Click again to sign what you've seen"));
  } else if (notice.standing === "continue") {
    buttons.push(accept(notice.head, "Got it", "Click again to sign that you've seen this"));
  } else if (notice.standing !== "waiting_for_history") {
    buttons.push(accept(notice.head, "Allow", "Click again to allow"));
    buttons.push(armedButton("Block", "Click again to block", "stop", (button) =>
      act(button, "/api/block", { agent: notice.contact })));
  }
  // The setting that held it, when one did. A rewritten history is held whatever the settings say.
  const held = notice.standing === "ask" || notice.standing === "hold"
    ? notice.since_accepted.map((change) => change.kind).find((kind) => CHANGE_NAMES[kind] && state.settings.changes[kind] !== "continue")
    : null;
  return el("div", { class: "card", id: `notice-${notice.contact}` },
    el("h3", {}, `${notice.label} changed`),
    held
      ? why(`You asked to approve it ${CHANGE_NAMES[held].charAt(0).toLowerCase()}${CHANGE_NAMES[held].slice(1)}.`, `change-${held}`, "and later ones carry on by themselves")
      : null,
    el("p", { class: "lead" }, held ? "Until then their messages wait on the host, and your agent can't write to them." : STANDINGS[notice.standing] || notice.standing),
    changeLines(notice.since_accepted, null),
    notice.rewritten_since && notice.rewritten_since.length
      ? changeLines(notice.rewritten_since, "The other history says")
      : null,
    buttons.length ? el("div", { class: "acts" }, ...buttons) : null,
    more(`notice-${notice.contact}`, "Details", exact(["Address", notice.address], ["ID", el("span", { class: "id" }, notice.contact)])));
}

function rulesBanners(rules, settings) {
  const banners = [];
  if (rules.ended) {
    banners.push(el("div", { class: "banner stop" },
      el("p", {}, "Your agent is stopped: its rules reached the end you gave them, so nothing moves until you sign rules without it.")));
  }
  if (settings.paused) {
    banners.push(el("div", { class: "banner" },
      el("p", {}, "You've paused your agent, so nothing moves until you sign settings that aren't paused.")));
  }
  return banners;
}

// Fixed words for each setting that lets more through than usual (`risky` in the state). They say
// what it means, and the person's choice stands.
const RISKY = {
  open_to_anyone: "Anyone can reach your agent, not only your contacts. Only approve what you asked it for.",
  full_auto: "Full auto: your agent says yes by itself to everything it may, up to Splint's limits. A price you'd pay is never agreed without your yes, and one it quotes waits for you unless you let quotes go by themselves.",
  sealing_off: "Unsealed: with contacts who also chose it, hosts can read what passes.",
  free_text_with_strangers: "People who aren't your contacts can send your agent their own words, which may be written to fool it.",
};

/** Settings that let more through than usual, said beside everything else, never instead of a check. */
function riskyBanners(risky) {
  return (risky || []).map((word) => el("div", { class: "banner" }, el("p", {}, RISKY[word] || "A setting lets more through than usual.")));
}

/** Who kept the agent busy today, busiest first, with anyone sending far more than on a usual day marked. */
function usagePart(usage) {
  if (!usage || !usage.length) return [];
  const busier = usage.filter((line) => line.busier_than_usual);
  return [
    ...busier.map((line) => el("div", { class: "banner" }, el("p", {},
      `${line.address} sent your agent ${line.arrivals_today} today, where a usual day is about ${line.usual_per_day}. Your settings limit what they can send in a day.`))),
    el("div", { class: "table" }, el("table", { class: "list usage" },
      el("thead", {}, el("tr", {}, el("th", {}, "Who"), el("th", {}, "Came today"), el("th", {}, "Usual day"), el("th", {}, "Notes in and out"), el("th", {}, "Requests in and out"))),
      el("tbody", {}, ...usage.map((line) => el("tr", { class: line.busier_than_usual ? "busier" : "" },
        el("td", {}, line.address),
        el("td", {}, String(line.arrivals_today)),
        el("td", {}, String(line.usual_per_day)),
        el("td", {}, `${line.texts_from} / ${line.texts_to}`),
        el("td", {}, `${line.new_requests_from} / ${line.new_requests_to}`)))))),
  ];
}

// Exchanges, as rows that open in place --------------------------------------------------------

function standingTag(standing) {
  if (standing === "blocked") return el("span", { class: "tag stop" }, "Blocked");
  if (standing === "not_in_rules") return el("span", { class: "tag warn" }, "Not a contact");
  if (standing === "guest") return el("span", { class: "tag" }, "One-use link");
  return null;
}

function wordsPart(exchange) {
  const id = `words-${exchange.request}`;
  return el("div", {},
    ...exchange.words_waiting.map((words) =>
      el("p", { class: "soft small" }, `Waiting for your agent's next step: "${words}"`)),
    field(...typedInput(id, `Write to ${exchange.with.label}`, state.max_words_chars,
      "Signed by you. They read it as untrusted words.")),
    el("div", { class: "acts" },
      el("button", {
        type: "button",
        class: "small",
        onClick: (click) => {
          if (justRedrawn()) return;
          act(click.target, "/api/words", { request: exchange.request, text: typed.get(id) || "" }, () => typed.delete(id));
        },
      }, "Sign and send")));
}

// A step that would commit the owner to an amount waits until the other side's person has set up their
// controls, as no owner has signed for their agent until then.
function heldForThemWords(exchange) {
  return `Your agent's ${exchange.held_for_their_controls} commits you to an amount, and ${exchange.with.label}'s person hasn't set up their controls yet. It waits, unsigned, until they have, and then goes, or comes here for your OK if your settings say so.`;
}

function exchangeRow(exchange) {
  const standing = exchange.with.standing;
  const caveat = exchange.other_side === "not_proven" && ["cancelled", "expired"].includes(exchange.state)
    ? " Their answer to the last step hasn't been seen, so this may have ended differently on their side."
    : exchange.other_side === "not_proven" && FINISHED.has(exchange.state)
      ? " Their side hasn't signed that it saw the last step."
      : "";
  const key = `card-${exchange.request}`;
  return el("details", {
    class: "row",
    id: `exchange-${exchange.request}`,
    open: unrolled.has(key),
    ontoggle: (event) => {
      if (event.target.open) {
        unrolled.add(key);
      } else {
        unrolled.delete(key);
      }
    },
  },
    el("summary", { class: "cells" },
      el("span", { class: "who" }, exchange.with.label, standingTag(standing)),
      el("span", { class: "what" }, typeName(exchange.type)),
      el("span", { class: "state" }, dot(STATE_DOTS[exchange.state] ?? "accent"), el("span", {}, STATES[exchange.state] || exchange.state)),
      el("span", { class: "when", title: when(exchange.last_at) }, short(exchange.last_at))),
    el("div", { class: "row-body" },
      el("p", { class: "soft small" }, `${exchange.role === "requester" ? "Your agent asked" : "They asked"} · last step ${when(exchange.last_at)}.${caveat}`),
      exchange.held_for_their_controls ? el("p", { class: "why" }, heldForThemWords(exchange)) : null,
      numbersNotMoney(exchange),
      dialogue(exchange),
      exchange.may_write ? wordsPart(exchange) : null,
      standing === "not_in_rules"
        ? el("div", { class: "acts" },
            armedButton("Block", "Click again to block", "stop small", (button) =>
              act(button, "/api/block", { agent: exchange.with.agent })))
        : null,
      more(`row-more-${exchange.request}`, "Details",
        exact(
          exchange.with.address ? ["Address", exchange.with.address] : null,
          ["Type", exchange.type],
          ["Their agent", el("span", { class: "id" }, exchange.with.agent)],
          ["Last step", utc(exchange.last_at)],
        ),
        el("p", { class: "foot-note" }, orderNote(exchange)))));
}

function exchangeTable(exchanges) {
  return el("div", { class: "table" },
    el("div", { class: "cells thead", ariaHidden: "true" },
      el("span", {}, "With"), el("span", {}, "What"), el("span", {}, "Status"), el("span", { class: "when" }, "Last")),
    ...exchanges.map(exchangeRow));
}

// One-use links -------------------------------------------------------------------------------

function linkTypes() {
  return state.types.filter((type) => type.link_fields);
}

function fieldKey(type, name) {
  return `${type}.${name}`;
}

function linkFieldInput(type, name, rule) {
  const key = fieldKey(type, name);
  const id = `link-${name}`;
  const label = fieldLabel(name).label;
  const remembered = linkForm.fields.get(key);
  if (rule.word || rule.one_of) {
    const options = (rule.word || rule.one_of).map(String);
    const chosen = remembered ?? options[0];
    linkForm.fields.set(key, chosen);
    const shown = (value) => (rule.word ? plainWord(value) : fieldValue(name, value));
    return select(id, label, chosen, options.map((value) => [value, shown(value)]), (value) => linkForm.fields.set(key, value));
  }
  if (rule.times) {
    const room = Math.min(rule.times.max, 5);
    const times = remembered || [];
    return [
      el("span", { class: "field-name" }, label, el("span", { class: "soft" }, ` · up to ${room}, they pick one`)),
      ...Array.from({ length: room }, (_, index) => {
        const input = el("input", { type: "datetime-local", id: `${id}-${index}`, value: times[index] || "", step: rule.times.grid_secs });
        input.addEventListener("input", () => {
          const now = linkForm.fields.get(key) || [];
          now[index] = input.value;
          linkForm.fields.set(key, now);
        });
        return input;
      }),
    ];
  }
  const numeric = Boolean(rule.range);
  const input = el("input", {
    type: numeric ? "number" : "text",
    id,
    value: remembered ?? "",
    autocomplete: "off",
    ...(numeric ? { min: rule.range.min, max: rule.range.max } : { maxLength: rule.text.max_chars }),
  });
  input.addEventListener("input", () => linkForm.fields.set(key, input.value));
  return [el("label", { htmlFor: id }, label), input];
}

function linkTerms(type) {
  const terms = {};
  for (const [name, rule] of Object.entries(type.link_fields)) {
    const value = linkForm.fields.get(fieldKey(type.name, name));
    if (rule.times) {
      const seconds = (value || []).filter(Boolean).map((text) => {
        const at = Math.floor(new Date(text).getTime() / 1000);
        // Moving a time here would sign one the owner didn't choose.
        if (at % rule.times.grid_secs) {
          throw new Error(`${fieldLabel(name).label} go every ${rule.times.grid_secs / 60} minutes, so choose a time on that.`);
        }
        return at;
      });
      terms[name] = [...new Set(seconds)].sort((one, other) => one - other);
    } else if (rule.word) {
      terms[name] = value;
    } else if (rule.text) {
      terms[name] = value || "";
    } else {
      terms[name] = Number(value);
    }
  }
  return terms;
}

function linkCard(link) {
  const copy = el("button", {
    type: "button",
    class: "small",
    onClick: async () => {
      try {
        await navigator.clipboard.writeText(link.url);
        tell("Copied. Send it however you like.", false);
      } catch {
        tell("This browser wouldn't copy it, so select the link and copy it yourself.", true);
      }
    },
  }, "Copy");
  return el("div", { class: "card link", id: `link-${link.request}` },
    el("h3", { class: "state" }, dot(link.state ? "accent" : ""), el("span", {}, typeName(link.interaction)),
      el("span", { class: "tag" }, STATES[link.state] || "Not yet at your host")),
    el("p", { class: "lead" }, `Open until ${when(link.deadline)}. Whoever holds it can answer once.`),
    el("div", { class: "line-box" }, el("p", { class: "id link-url" }, link.url), copy));
}

function linksPart() {
  const types = linkTypes();
  if (!types.length) {
    return [emptyState("No links to make", "None of the types installed here can go to someone with no agent.")];
  }
  const chosen = types.find((type) => type.name === linkForm.type) || types[0];
  linkForm.type = chosen.name;
  const fields = Object.entries(chosen.link_fields).map(([name, rule]) => field(...linkFieldInput(chosen.name, name, rule)));
  const go = armedButton("Make a link", "Click again to sign it", "main", (button) => {
    let terms;
    try {
      terms = linkTerms(chosen);
    } catch (failure) {
      tell(failure.message, true);
      return;
    }
    act(button, "/api/guest-link", {
      type: chosen.name,
      terms,
      days: Number(linkForm.days),
      subject: typed.get("link-subject") || null,
      note: typed.get("link-note") || null,
    }, () => {
      typed.delete("link-subject");
      typed.delete("link-note");
      linkForm.fields.clear();
    });
  });
  const open = state.links.filter((link) => !link.state || link.state === "offered");
  return [
    el("p", { class: "group-note" }, "For someone with no agent. You sign the offer here, and they can only say yes, no or ask. A link is never sealed: your host serves the page they answer on, so it can read the offer and their answer."),
    el("div", { class: "group" },
      field(...select("link-type", "Type", chosen.name, types.map((type) => [type.name, typeName(type.name)]), (value) => {
        linkForm.type = value;
        render();
      })),
      ...fields,
      field(...select("link-days", "Open for", String(linkForm.days), [["1", "1 day"], ["3", "3 days"], ["7", "7 days"], ["14", "14 days"]], (value) => {
        linkForm.days = Number(value);
      })),
      field(...typedInput("link-subject", "Subject", state.max_subject_chars, "Optional. Your agent doesn't see it.")),
      field(...typedInput("link-note", "Note", 200, "Optional")),
      el("div", { class: "field" }, el("div", { class: "acts" }, go))),
    // Once it's answered there's nothing to pass on, and it's in the exchanges.
    ...(open.length ? [el("div", { class: "label" }, el("h2", {}, "Waiting for an answer", el("span", { class: "count" }, String(open.length))))] : []),
    ...open.map(linkCard),
  ];
}

// History -------------------------------------------------------------------------------------

// What was refused, in a person's words. The reasons are fixed words from Signet and hosts, so a
// reason this doesn't know yet still reads as a refusal, with its word in Details.
const REFUSED_OUT = {
  not_a_contact: "Your agent tried to message someone who isn't a contact",
  stopped: "Your agent tried to send while it was stopped",
  over_limit: "Your agent tried to go past a limit you set",
  text_off: "Your agent tried to send words where you haven't allowed them",
  too_many_texts: "Your agent sent one contact more messages than a day allows",
  too_many_new_requests: "Your agent tried to start too many things at once",
  type_not_allowed: "Your agent tried a kind of exchange you haven't allowed",
  unknown_type: "Your agent tried a kind of exchange that isn't installed",
  approval_missing: "Your agent tried something that needs your yes",
  after_deadline: "Your agent answered after the deadline",
  not_offered: "Your agent picked something that wasn't offered",
  out_of_turn: "Your agent moved out of turn",
  not_a_valid_call: "Your agent sent something that couldn't be read",
  not_text: "Your agent sent a step as words",
  malformed: "Your agent sent something that couldn't be read",
};
const REFUSED_IN = {
  not_admitted: "Someone your rules don't let in tried to reach your agent",
  bad_signature: "A step sent to your agent had a signature that didn't check out",
  bad_signature_or_dates: "A step sent to your agent didn't check out",
  replay: "A step already received was sent again",
};

function refusedWords(line) {
  const known = line.way === "in" ? REFUSED_IN[line.reason] : REFUSED_OUT[line.reason];
  if (known) return known;
  return line.way === "in" ? "A step sent to your agent didn't check out" : "Something your agent tried was refused";
}

function refusedRow(line) {
  return el("tr", {},
    el("td", { class: "when", title: when(line.at) }, short(line.at)),
    el("td", {},
      refusedWords(line),
      line.count > 1 ? el("span", { class: "soft" }, ` · ${line.count} times`) : null,
      showIds
        ? el("div", { class: "id" }, [
            line.reason,
            line.call,
            line.by === "host" ? "your host's word" : "your Signet",
            line.from ? `from ${line.from}` : null,
          ].filter(Boolean).join(" · "))
        : null));
}

function refusedPart() {
  if (!state.refused.length && !state.refused_unknown) return [];
  return [
    state.refused_unknown ? el("p", { class: "group-note" }, "Your host can't be reached, so what it refused isn't listed right now.") : null,
    state.refused.length
      ? el("div", { class: "table" },
          el("table", { class: "list" },
            el("thead", {}, el("tr", {}, el("th", {}, "When"), el("th", {}, "What happened"))),
            el("tbody", {}, ...state.refused.slice(0, 50).map(refusedRow))))
      : null,
    el("p", { class: "group-note" }, "Nothing anyone wrote is kept here."),
  ].filter(Boolean);
}

// A readable copy of every exchange this page was given, as plain text the owner keeps.
function historyText() {
  const out = [
    `Splint history for ${state.me.address}, saved ${when(Date.now() / 1000)}`,
    "Written by the owner's page from the signed steps it read from Signet. Words in quotes are only what someone wrote.",
    "",
  ];
  for (const exchange of state.exchanges) {
    out.push(`== ${exchange.with.label} (${exchange.with.address}), ${exchange.type}, ${STATES[exchange.state] || exchange.state}`);
    for (const line of exchange.lines) {
      out.push(`${[line.who, ORIGINS[line.origin], `${when(line.at)} (${utc(line.at)})`].filter(Boolean).join(" · ")}`);
      out.push(`  ${line.says}`);
    }
    out.push("");
  }
  if (state.exchanges_left_out) out.push(`${count(state.exchanges_left_out, "older exchange")} not included.`);
  return out.join("\n");
}

function saveCopy() {
  const file = new Blob([historyText()], { type: "text/plain;charset=utf-8" });
  const address = URL.createObjectURL(file);
  const anchor = el("a", { href: address, download: `splint-history-${new Date().toISOString().slice(0, 10)}.txt` });
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(address), 1000);
}

// Where this owner's history is, and what's kept, as the code really does it.
function keptPart() {
  const where = state.elsewhere ? "on the device your agent runs on" : "on this device";
  const facts = [
    `Your exchanges stay ${where}, in ~/.splint/signet. Nothing deletes them yet.`,
    `This page keeps no copy, and shows the newest ${MAX_EXCHANGES_SHOWN}.`,
    "Hosts clear what a message says once it's delivered or expired.",
  ];
  return [
    el("div", { class: "card" },
      el("ul", { class: "facts" }, ...facts.map((words) => el("li", {}, words))),
      el("div", { class: "acts" },
        el("button", { type: "button", class: "small", id: "save-copy", onClick: saveCopy }, "Save a copy"))),
  ];
}

// Settings ------------------------------------------------------------------------------------

function settingsNow() {
  return edits || state.settings;
}

function edit(change) {
  if (!edits) edits = structuredClone(state.settings);
  change(edits);
  redrawSettings();
}

function select(id, label, value, options, onChange) {
  const input = el("select", { id }, ...options.map(([word, words]) =>
    el("option", { value: word, selected: word === value }, words)));
  input.addEventListener("change", () => onChange(input.value));
  return [el("label", { htmlFor: id }, label), input];
}

function checkbox(id, label, checked, onChange) {
  const input = el("input", { type: "checkbox", id, checked, role: "switch" });
  input.addEventListener("change", () => onChange(input.checked));
  return el("label", { class: "inline", htmlFor: id }, input, el("span", {}, label));
}

function linesInput(id, label, value, onChange, help) {
  const input = el("textarea", { id, value, spellcheck: false });
  input.addEventListener("change", () => onChange(input.value));
  return [el("label", { htmlFor: id }, label), input, el("p", { class: "soft small" }, help)];
}

function wordsOn(text) {
  return text.split("\n").map((line) => line.trim()).filter(Boolean);
}

function hostsFrom(text) {
  return wordsOn(text).map((line) => {
    const [domain, key] = line.split(/\s+/);
    return { domain, key: key || "" };
  });
}

function reachPart(settings) {
  const inbound = settings.reach.inbound;
  const letting = inbound.from !== "contacts";
  const fields = [
    field(...select("reach-from", "Besides your contacts", inbound.from, [
      ["contacts", "Nobody else"],
      ["open", "Anyone"],
      ["filter", "Whoever fits a filter"],
    ], (word) => edit((all) => { all.reach.inbound.from = word; }))),
  ];
  if (inbound.from === "filter") {
    fields.push(
      field(checkbox("reach-past", "Anyone your agent has written to before", inbound.filter.past, (on) =>
        edit((all) => { all.reach.inbound.filter.past = on; }))),
      field(...linesInput("reach-owners", "Agents acting for these owners", inbound.filter.owners.join("\n"), (text) =>
        edit((all) => { all.reach.inbound.filter.owners = wordsOn(text); }), "One owner's ID on each line.")),
      field(...linesInput("reach-hosts", "Agents on these hosts", inbound.filter.hosts.map((host) => `${host.domain} ${host.key}`).join("\n"), (text) =>
        edit((all) => { all.reach.inbound.filter.hosts = hostsFrom(text); }), "One host on each line: its domain, a space, and the key it signs deliveries with.")));
  }
  if (letting) {
    fields.push(
      field(
        el("span", { class: "field-name" }, "What they may use"),
        ...state.types.map((type) =>
          checkbox(`reach-type-${type.name}`, typeName(type.name), inbound.types.includes(type.name), (on) =>
            edit((all) => {
              const types = all.reach.inbound.types.filter((name) => name !== type.name);
              all.reach.inbound.types = on ? [...types, type.name] : types;
            }))),
        checkbox("reach-text", "They may send words they chose. Those reach your agent marked untrusted.", inbound.text, (on) =>
          edit((all) => { all.reach.inbound.text = on; }))));
  }
  fields.push(
    field(...select("reach-strangers", "Anyone else who writes", inbound.strangers, [
      ["quarantine", "Waits here for you, unseen by your agent"],
      ["block", "Is dropped, and they can't tell"],
    ], (word) => edit((all) => { all.reach.inbound.strangers = word; }))),
    field(...select("reach-outbound", "Whom your agent may start something with", settings.reach.outbound, [
      ["contacts", "Only your contacts"],
      ["replies", "Also anyone let in who has written to it"],
    ], (word) => edit((all) => { all.reach.outbound = word; }))));
  return el("fieldset", { class: "group" }, ...fields);
}

function capInputs(settings) {
  return state.types.flatMap((type) => type.values.map((name) => {
    const caps = settings.permissions.caps[type.name] || {};
    const id = `cap-${type.name}-${name}`;
    const input = el("input", {
      type: "number",
      id,
      min: 0,
      value: caps[name] === undefined ? "" : String(caps[name]),
      placeholder: "No cap",
    });
    input.addEventListener("change", () => edit((all) => {
      const found = all.permissions.caps[type.name] || {};
      if (input.value === "") {
        delete found[name];
      } else {
        found[name] = Number(input.value);
      }
      if (Object.keys(found).length) {
        all.permissions.caps[type.name] = found;
      } else {
        delete all.permissions.caps[type.name];
      }
    }));
    const [base, unitWord] = name.split(".");
    const { label, unit } = fieldLabel(base);
    const unitWords = unitWord ? ` (${unitWord.toUpperCase()})` : unit ? ` (${unit("").trim()})` : "";
    return field(el("label", { htmlFor: id }, `Highest ${label.toLowerCase()} your agent offers or takes up on ${typeName(type.name)}${unitWords}`), input);
  }));
}

function permissionsPart(settings) {
  const level = settings.permissions.level;
  const day = el("input", {
    type: "number",
    id: "actions-per-day",
    min: 0,
    max: 2500,
    value: String(settings.permissions.actions_per_day),
  });
  day.addEventListener("change", () => edit((all) => { all.permissions.actions_per_day = Number(day.value); }));
  return [
    el("fieldset", { class: "group" },
      field(...select("level", "How much your agent may do with nobody there", level, [
        ["ask_me", "Ask me first: nothing you'd be held to goes out until you say yes"],
        ["auto_within_limits", "Go ahead: under the limits below, and while this device is on it signs the final yes on a kind you sign, where there's no amount in it"],
        // Shown only where rules signed elsewhere hold it, as `splint authorize --level full-auto` can.
        ...(level === "full_auto" ? [["full_auto", "Full auto, set outside this page: everything with no amount in it, up to 2,500 actions a day, and amounts wait for me unless I say below"]] : []),
      ], (word) => edit((all) => { all.permissions.level = word; }))),
      ...(level === "full_auto"
        ? []
        : [field(el("label", { htmlFor: "actions-per-day" }, "Steps and messages your agent may send in a day"), day), ...capInputs(settings)]),
      ...(level === "ask_me"
        ? []
        : [field(...select("quoted-prices", "A price your agent quotes, where you'd be the one paid", settings.permissions.quoted_prices || "wait", [
            ["wait", "Waits for me (the default)"],
            ["within_limits", "Goes ahead by itself, within the limits here"],
          ], (word) => edit((all) => {
            // Left out for the default, as the signed rules leave it out.
            if (word === "wait") delete all.permissions.quoted_prices;
            else all.permissions.quoted_prices = word;
          })))])),
    el("p", { class: "group-note" }, "Your agent's model decides what to do. These are ceilings it can't pass, enforced in code. While it's on, your device gives the final yes on a kind you sign, where there's no amount in it, and nothing else. Anything you'd pay always waits for you."),
  ];
}

const ANSWERS = [
  ["continue", "Carry on, and tell me"],
  ["ask", "Stop, and ask me"],
  ["hold", "Stop until I say otherwise"],
];
const CHANGE_NAMES = {
  owner: "When a contact gets a new owner",
  key: "When a contact replaces its key",
  signet: "When a contact moves its Signet",
  host: "When a contact moves host",
  revocation: "When a contact stops acting for its owner",
  declared: "When a contact's owner declares a change",
};

function changesPart(settings) {
  return [
    el("fieldset", { class: "group" },
      ...Object.entries(CHANGE_NAMES).map(([kind, label]) =>
        field(...select(`change-${kind}`, label, settings.changes[kind], ANSWERS, (word) =>
          edit((all) => { all.changes[kind] = word; }))))),
    el("p", { class: "group-note" }, "A history that rewrites what you've already seen is always held, whatever you choose here."),
  ];
}

const SEALING_EXPLAINED = "https://github.com/nennovate/splint/blob/main/docs/how-it-works.md#sealed-and-unsealed";
const SEALING = [
  ["sealed", "Sealed: only your agent and theirs can read what's said"],
  ["unsealed", "Unsealed: both agents' hosts can read it as it passes"],
];

function sealingPart(settings) {
  return [
    el("fieldset", { class: "group" },
      field(...select("sealing", "What your agent says and hears", settings.sealing, SEALING, (word) =>
        edit((all) => { all.sealing = word; })))),
    el("p", { class: "group-note" },
      "If either of you chose sealed, everything between your two agents is sealed, both ways. Unsealed lets a host look at what passes, to help keep you safe, and sees all of it. Either side can still show anything signed to anyone later, with proof it's real."),
    el("p", { class: "group-note" },
      "Sealed means more privacy, at the cost of less protection from your own host, which can then check only the outside of what your agent sends. ",
      el("a", { href: SEALING_EXPLAINED, target: "_blank", rel: "noopener noreferrer" }, "What this means"),
      ", or run splint guide sealed."),
  ];
}

function settingsProblem(settings) {
  const filter = settings.reach.inbound.filter;
  if (settings.reach.inbound.from === "filter") {
    if (!filter.owners.every((id) => AN_ID.test(id))) return "An owner's ID looks like splint1 and 64 more characters.";
    if (!filter.hosts.every((host) => host.domain && host.key)) return "Each host needs a domain and a key.";
  }
  const day = settings.permissions.actions_per_day;
  if (!Number.isInteger(day) || day < 0 || day > 2500) return "Steps and messages in a day is a whole number up to 2,500.";
  return null;
}

function groupLabel(title) {
  return el("div", { class: "label" }, el("h2", {}, title));
}

/**
 * Contacts the agent added by itself that these settings would take out, as Ask me first does, since
 * then only contacts the owner chose count. Who they are is said before anything's signed,
 * and the program behind the page reads them again rather than going by this.
 */
function addedTakenOut(settings) {
  const lets = (one) => Boolean(one.reach.agreed) && one.permissions.level !== "ask_me";
  if (!lets(state.settings) || lets(settings)) return [];
  return state.invites.filter((invite) => invite.added_by_agent);
}

function addedPart(settings, added) {
  if (!added.length) return [];
  const why = settings.reach.agreed
    ? "At Ask me first, only contacts you chose can reach your agent"
    : "With contacts your agent adds turned off, only contacts you chose can reach it";
  const reach = settings.reach.agreed ? "under Ask me first" : "with contacts your agent adds turned off";
  const option = (word, id, label, words) => {
    const input = el("input", { type: "radio", name: "added-choice", id, value: word, checked: keepChoice === word });
    input.addEventListener("change", () => { keepChoice = word; redrawSettings(); });
    return el("label", { class: "inline", htmlFor: id }, input, el("span", {}, el("strong", {}, label), ` ${words}`));
  };
  return [
    el("div", { class: "group", id: "added-taken-out" },
      el("p", {}, `${why}, so these settings take out the contacts it added by itself: ${added.map((invite) => invite.address).join(", ")}. They're dropped unless you choose to keep them before you sign.`),
      field(option("keep", "keep-added", "Keep them.", `They become your own contacts, as if you'd added them: they can reach your agent ${reach}, and amounts with them follow your setting for prices, as with anyone you added.`)),
      field(option("drop", "drop-added", "Drop them.", "They're taken out, and Contacts lists any of them for you to add back."))),
  ];
}

function settingsBody() {
  const settings = settingsNow();
  const problem = settingsProblem(settings);
  const unsaved = edits !== null && JSON.stringify(edits) !== JSON.stringify(state.settings);
  const added = addedTakenOut(settings);
  const shownFor = added.map((invite) => invite.agent).sort().join(" ");
  if (shownFor !== keepChoiceFor) {
    keepChoice = added.length ? "drop" : null;
    keepChoiceFor = shownFor;
  }
  const unchosen = added.length > 0 && keepChoice === null;
  return [
    groupLabel("Who can reach your agent"),
    reachPart(settings),
    groupLabel("What it may do alone"),
    ...permissionsPart(settings),
    ...addedPart(settings, added),
    groupLabel("When a contact changes"),
    ...changesPart(settings),
    groupLabel("Sealed or unsealed"),
    ...sealingPart(settings),
    groupLabel("Pause"),
    el("div", { class: "group" },
      field(checkbox("paused", "Pause your agent: nothing moves until you sign settings without this", settings.paused, (on) =>
        edit((all) => { all.paused = on; })))),
    unsaved || problem
      ? el("div", { class: "sign-bar" },
          el("p", { class: "unsaved" }, problem || (unchosen ? "Choose whether to keep the contacts your agent added, above, before you sign." : "Not signed yet, so none of this counts until you do.")),
          el("div", { class: "acts" },
            unsaved && !problem && !unchosen
              ? armedButton("Sign these settings", "Click again to sign", "main", (button) =>
                  act(button, "/api/settings", added.length ? { ...edits, added: { shown: added.map((invite) => invite.agent), choice: keepChoice } } : edits, () => { edits = null; keepChoice = null; }))
              : null,
            unsaved
              ? el("button", { type: "button", onClick: () => { edits = null; keepChoice = null; redrawSettings(); } }, "Undo my changes")
              : null))
      : el("p", { class: "group-note" }, `Signed by you on ${when(state.rules.signed_at)}, ${state.rules.ends_at ? `until ${when(state.rules.ends_at)}` : "in force until you sign others"}.`),
  ];
}

// Where the person gets paid, which their agent can ask to be paid at once a deal that pays them is
// done. Signed on its own, apart from the settings, as `splint get-paid` signs it, and each place is
// checked again on this device before anything is signed.
function gettingPaidPart() {
  const id = "where-paid";
  const box = el("textarea", {
    id, rows: 4, spellcheck: false, autocomplete: "off", value: typed.get(id) || "",
    placeholder: "https://pay.example.com/you\nyou@wallet.example\nonchain:eip155:8453:0x...:usdc",
  });
  box.addEventListener("input", () => typed.set(id, box.value));
  return [el("div", { class: "card" },
    el("label", { htmlFor: id }, "Up to 4 places people can pay you, one a line: a payment link or page, a Lightning address, or onchain:CHAIN:ADDRESS:ASSET. No bank details."),
    box,
    el("p", { class: "soft small" }, "Splint holds no money. Once a deal that pays you is done, your agent can ask to be paid at one of these, with the amount from the deal, and people pay you on their own app or wallet. A payment by Lightning or on a chain can't be reversed. Signing new places replaces the ones before, and the people you deal with are told they're new."),
    el("div", { class: "acts" }, armedButton("Sign where you get paid", "Click again to sign", "", (button) =>
      act(button, "/api/get-paid", { places: wordsOn(box.value) }, () => typed.delete(id)))))];
}

function redrawSettings() {
  const holder = document.getElementById("settings-body");
  if (!holder) return;
  const focused = document.activeElement && document.activeElement.id;
  holder.replaceChildren(...settingsBody());
  const again = focused && document.getElementById(focused);
  if (again) again.focus();
}

// Contacts ------------------------------------------------------------------------------------

function contactRow(contact) {
  const forget = armedButton("Remove", "Click again to sign", "small", (button) =>
    act(button, "/api/forget", { agent: contact.agent }));
  const status = contact.blocked
    ? [dot("stop"), "Blocked"]
    : contact.invited
      ? [dot("accent"), "Invited"]
      : [dot("good"), "Contact"];
  return el("tr", { id: `contact-${contact.agent}` },
    el("td", { class: "name" },
      contact.label,
      el("span", { class: "soft" }, contact.never_a_contact ? "Never a contact" : contact.address),
      showIds ? el("span", { class: "id" }, contact.agent) : null),
    el("td", { class: "soft small" },
      [contact.types.map(typeName).join(", "), !contact.blocked && contact.text ? "words" : ""].filter(Boolean).join(" · ") || "Nothing"),
    el("td", {}, el("span", { class: "state" }, ...status)),
    el("td", { class: "soft small", title: contact.sealed_why }, contact.sealed ? "Sealed" : "Unsealed",
      el("span", { class: "soft" }, contact.sealed_why)),
    el("td", { class: "acts-cell" },
      contact.blocked
        ? contact.never_a_contact
          ? null
          : armedButton("Unblock", "Click again to sign", "small", (button) => act(button, "/api/unblock", { agent: contact.agent }))
        : armedButton("Block", "Click again to block", "stop small", (button) => act(button, "/api/block", { agent: contact.agent })),
      forget));
}

function lineCard(me) {
  const copy = el("button", {
    type: "button",
    class: "small",
    onClick: async () => {
      try {
        await navigator.clipboard.writeText(me.line);
        tell("Copied.", false);
      } catch {
        tell("This browser wouldn't copy it, so select it and copy it yourself.", true);
      }
    },
  }, "Copy");
  return el("div", { class: "card" },
    el("h3", {}, "Your line"),
    el("p", { class: "lead" }, "Give this to anyone your agent should reach. It isn't secret."),
    el("div", { class: "line-box" }, el("p", { class: "id", id: "my-line" }, me.line), copy));
}

function contactsTable(contacts) {
  if (!contacts.length) return emptyState("No contacts yet", "Give someone your line, or let in someone who's waiting.");
  return el("div", { class: "table" },
    el("table", { class: "list" },
      el("thead", {}, el("tr", {}, el("th", {}, "Name"), el("th", {}, "May use"), el("th", {}, "Status"), el("th", {}, "Sealed"), el("th", {}))),
      el("tbody", {}, ...contacts.map(contactRow))));
}

// The page ------------------------------------------------------------------------------------

function statusLine(now, waitingCount) {
  const parts = [];
  if (now.rules.ended) {
    parts.push(dot("stop"), el("span", {}, "Stopped"));
  } else if (now.settings.paused) {
    parts.push(dot("warn"), el("span", {}, "Paused"));
  } else if (waitingCount) {
    parts.push(dot("accent", true), el("span", {}, `${waitingCount} ${waitingCount === 1 ? "needs" : "need"} your OK`));
  } else {
    parts.push(dot("good"), el("span", {}, "Nothing needs you"));
  }
  if (now.elsewhere) {
    parts.push(el("span", {}, now.heard_at
      ? `· On another device, last heard ${short(now.heard_at)}`
      : "· On another device, not heard from yet"));
  }
  return parts;
}

function tabs(waitingCount) {
  return VIEWS.map(([name, words]) => el("button", {
    type: "button",
    role: "tab",
    id: `tab-${name}`,
    ariaSelected: String(view === name),
    onClick: () => {
      if (view === name) return;
      openView(name);
      window.scrollTo(0, 0);
    },
  }, words, name === "now" && waitingCount ? el("span", { class: "badge" }, String(waitingCount)) : null));
}

function openView(name) {
  view = name;
  try {
    sessionStorage.setItem(VIEW_KEY, name);
  } catch {
    // Only which view opens next time.
  }
  render();
}

function viewOf(name, ...parts) {
  return el("div", { class: "view", id: `view-${name}`, role: "tabpanel", hidden: view !== name },
    ...parts.filter(Boolean));
}

function render() {
  const now = state;
  const signing = now.exchanges.filter((exchange) => exchange.to_sign.length);
  const moving = now.exchanges.filter((exchange) => !exchange.to_sign.length && !FINISHED.has(exchange.state));
  const finished = now.exchanges.filter((exchange) => !exchange.to_sign.length && FINISHED.has(exchange.state));
  const held = now.changes.filter((notice) => notice.standing !== "continue");
  const told = now.changes.filter((notice) => notice.standing === "continue");
  const waiting = [
    ...now.starting.map((starting) => decisionCard(starting, starting.to_sign)),
    ...signing.flatMap((exchange) => exchange.to_sign.map((toSign) => decisionCard(exchange, toSign))),
    ...held.map(noticeCard),
    ...now.kinds.map(kindCard),
    ...now.waiting.map(strangerCard),
  ];
  // Held whatever the owner's settings say, because something about them doesn't check out.
  const alwaysHeld = held.some((notice) => notice.standing === "rewritten" || notice.standing === "waiting_for_history")
    || now.waiting.some((stranger) => stranger.disagreed);
  const focused = document.activeElement && document.activeElement.id;
  /** @type {HTMLElement} */ (document.getElementById("title")).textContent = now.me.address;
  const needsOk = waiting.length + now.invites.length;
  /** @type {HTMLElement} */ (document.getElementById("me")).replaceChildren(...statusLine(now, needsOk));
  /** @type {HTMLElement} */ (document.getElementById("tabs")).replaceChildren(...tabs(needsOk));
  const main = /** @type {HTMLElement} */ (document.getElementById("main"));
  main.replaceChildren(
    ...rulesBanners(now.rules, now.settings),
    ...(now.unreadable
      ? [el("div", { class: "banner stop" }, el("p", {}, `${count(now.unreadable, "exchange")} from your agent's Signet ${now.unreadable === 1 ? "doesn't" : "don't"} check out, so ${now.unreadable === 1 ? "it isn't" : "they aren't"} shown. That's a Signet changed or lying, or its files damaged.`))]
      : []),
    viewOf("now",
      section("waiting", "Needs your OK", [
        ...(waiting.length ? [el("p", { class: "group-note" }, alwaysHeld
          ? "Your settings leave these to you, apart from what doesn't check out."
          : "These wait only because your settings leave them to you.")] : []),
        ...waiting,
        ...(now.waiting_unknown ? [el("p", { class: "group-note" }, "Your host can't be reached, so anyone held there isn't listed right now.")] : []),
      ], { empty: emptyState("Nothing needs your OK", "What your settings leave to you waits here."), total: waiting.length }),
      section("invites", "Invites", now.invites.map(inviteCard), { total: now.invites.length }),
      section("changed", "What changed", told.map(noticeCard)),
      section("exchanges", "Going on", moving.length ? [exchangeTable(moving)] : [], { total: moving.length }),
      section("usage", "Who kept your agent busy today", usagePart(now.usage))),
    viewOf("history",
      section("finished", "Finished", [
        ...(finished.length ? [exchangeTable(finished)] : []),
        ...(now.exchanges_left_out ? [el("p", { class: "group-note" }, `${count(now.exchanges_left_out, "older exchange")} not shown.`)] : []),
      ], { empty: emptyState("Nothing finished yet", null), total: finished.length }),
      section("refused", "Refused", refusedPart(), { empty: emptyState("Nothing has been refused", null), aside: idsToggle() }),
      section("kept", "Where it's kept", keptPart())),
    viewOf("contacts",
      section("contacts", "Contacts", [contactsTable(now.contacts)], { total: now.contacts.length, aside: idsToggle() }),
      section("line", "Share", [lineCard(now.me)])),
    viewOf("links", section("links", "One-use links", linksPart())),
    viewOf("settings",
      section("settings", null, [...riskyBanners(now.risky), el("div", { id: "settings-body" }, ...settingsBody())]),
      section("getting-paid", "Getting paid", gettingPaidPart())));
  lastRedraw = performance.now();
  const again = focused && document.getElementById(focused);
  if (again) again.focus();
}

async function refresh() {
  const found = await call("/api/state");
  const text = JSON.stringify(found);
  if (text !== lastText) {
    lastText = text;
    state = found;
    render();
  }
}

async function poll() {
  if (document.visibilityState === "visible") {
    try {
      await refresh();
    } catch (failure) {
      tell(failure.message, true);
    }
  }
  setTimeout(poll, REFRESH_MILLIS);
}

function start() {
  secret = takeSecret();
  try {
    const remembered = sessionStorage.getItem(VIEW_KEY);
    if (VIEWS.some(([name]) => name === remembered)) view = /** @type {string} */ (remembered);
  } catch {
    // The first view, then.
  }
  if (!secret) {
    /** @type {HTMLElement} */ (document.getElementById("title")).textContent = "Open your link";
    const main = /** @type {HTMLElement} */ (document.getElementById("main"));
    main.replaceChildren(emptyState("This page needs its link", "Open the link that splint page printed when it started."));
    return;
  }
  poll();
}

start();
