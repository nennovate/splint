// @ts-check
// What both owner pages draw the same way: the page on an owner's own device, and "your controls", the
// page Splint on the owner's computer serves at /owner. Everything from a counterparty arrives as data
// and goes on the screen as text: these only ever make elements and set their text, and never write
// markup. Words that hide what they say are shown as codes, and a page never asks for a yes to them.
"use strict";

/**
 * The only way anything reaches the page. Strings become text nodes, never markup.
 * @param {string} tag
 * @param {Record<string, any> | null} props
 * @param {...(Node | string | null | undefined)} kids
 */
function el(tag, props, ...kids) {
  const made = /** @type {any} */ (document.createElement(tag));
  for (const [name, value] of Object.entries(props || {})) {
    if (name === "onClick") {
      made.addEventListener("click", value);
    } else if (name === "class") {
      made.className = value;
    } else {
      made[name] = value;
    }
  }
  for (const kid of kids) {
    if (kid !== null && kid !== undefined) {
      made.append(kid);
    }
  }
  return made;
}

function when(seconds) {
  return new Date(seconds * 1000).toLocaleString(undefined, {
    weekday: "short",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZoneName: "short",
  });
}

// For a list, where the full date is one step away: a time today, a day this year, or a date.
function short(seconds) {
  const at = new Date(seconds * 1000);
  const now = new Date();
  if (at.toDateString() === now.toDateString()) {
    return at.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
  }
  return at.toLocaleDateString(undefined, at.getFullYear() === now.getFullYear()
    ? { month: "short", day: "numeric" }
    : { year: "numeric", month: "short", day: "numeric" });
}

// The exact time, for Details, beside the local one a person reads.
function utc(seconds) {
  return `${new Date(seconds * 1000).toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

function capital(words) {
  return words.charAt(0).toUpperCase() + words.slice(1);
}

// A word from a type's own list, such as in_person, as words. Those lists hold only a to z, digits
// and underscores, so this can't make two of them read the same.
function plainWord(word) {
  return capital(String(word).replaceAll("_", " "));
}

// A type's name, such as meeting/1, as a person says it. The version stays in Details.
function typeName(type) {
  return plainWord(String(type).split("/")[0]);
}

// What a field's last word says about its unit. Field names are a schema's own words, so this is
// general: any type's duration_min reads "Duration" in minutes.
const UNITS = {
  min: (number) => `${number} min`,
  mins: (number) => `${number} min`,
  minutes: (number) => `${number} min`,
  sec: (number) => `${number} sec`,
  secs: (number) => `${number} sec`,
  seconds: (number) => `${number} sec`,
  hours: (number) => `${number} hr`,
  days: (number) => (number === "1" ? "1 day" : `${number} days`),
  kb: (number) => `${number} KB`,
  mb: (number) => `${number} MB`,
  pct: (number) => `${number}%`,
  minor: (number) => `${number} in minor units`,
};

/** @returns {{label: string, unit: ((number: string) => string) | null}} */
function fieldLabel(name) {
  const words = String(name).split("_").filter(Boolean);
  const last = words.length > 1 ? words[words.length - 1] : "";
  const unit = Object.hasOwn(UNITS, last) ? UNITS[last] : null;
  return { label: capital((unit ? words.slice(0, -1) : words).join(" ")), unit };
}

// ISO 4217 minor units. Browsers' display digits differ from these for some currencies, such as HUF.
const MINOR_DIGITS = { USD: 2, EUR: 2, GBP: 2, CAD: 2, AUD: 2, CHF: 2, JPY: 0, KWD: 3, BHD: 3 };

/**
 * An amount in a currency's minor units as a person reads it, such as 125000 in usd as "1,250.00 USD",
 * by ISO 4217's digits for the currencies listed, and in minor units for any other, rather than guess.
 * Split on the digits as written, never divided as a float, which loses the last digit of a large one.
 */
function money(minor, currency) {
  const code = withHiddenShown(String(currency)).toUpperCase();
  const exact = String(minor);
  const digits = Object.hasOwn(MINOR_DIGITS, code) ? MINOR_DIGITS[code] : null;
  if (digits === null || !/^\d+$/.test(exact) || !Number.isSafeInteger(Number(exact))) return `${exact} in minor units of ${code}`;
  const padded = exact.padStart(digits + 1, "0");
  const whole = Number(padded.slice(0, padded.length - digits)).toLocaleString();
  if (!digits) return `${whole} ${code}`;
  const point = new Intl.NumberFormat().formatToParts(1.5).find((part) => part.type === "decimal");
  return `${whole}${point ? point.value : "."}${padded.slice(padded.length - digits)} ${code}`;
}

/**
 * The currency a value in minor units is in: the word in the field its type's `units` names for it, as
 * the owner's caps read it, from the value's own fields first and then the offer's. With no `units`
 * naming one, there's none, and the value reads in minor units rather than in a guessed currency.
 * @param {string} name
 * @param {any} terms
 * @param {Record<string, string> | undefined} units
 * @param {boolean} delivered
 */
function currencyOf(name, terms, units, delivered) {
  const unit = units && Object.hasOwn(units, name) ? units[name] : null;
  if (typeof unit !== "string" || !terms) return null;
  for (const fields of delivered ? [terms.result, terms.agreed] : [terms.agreed]) {
    if (fields && Object.hasOwn(fields, unit)) {
      const named = fields[unit];
      return typeof named === "string" && /^[a-z]{3}$/i.test(named) ? named : null;
    }
  }
  return null;
}

/**
 * A field's value in words, in its currency where it's in minor units and its type's `units` name the
 * field that says which.
 * @param {string} name
 * @param {string | number} number
 * @param {any} [terms]
 * @param {Record<string, string>} [units]
 * @param {boolean} [delivered]
 */
function fieldValue(name, number, terms, units, delivered) {
  const { unit } = fieldLabel(name);
  const exact = String(number);
  const currency = unit === UNITS.minor ? currencyOf(name, terms, units, Boolean(delivered)) : null;
  if (currency) return money(exact, currency);
  // Grouped only while a browser holds the number exactly. Details has it as signed either way.
  const text = /^\d+$/.test(exact) && Number.isSafeInteger(Number(exact)) ? Number(exact).toLocaleString() : exact;
  return unit ? unit(text) : text;
}

function exact(...pairs) {
  return el("dl", { class: "exact" }, ...pairs.filter(Boolean).flatMap(([name, value]) => [el("dt", {}, name), el("dd", {}, value)]));
}

function count(number, word) {
  return number === 1 ? `1 ${word}` : `${number} ${word}s`;
}

// One row of what's signed, in plain words. Rust says what each value is, so nothing is guessed: a
// party is the name Signet checked for its IDs, a time is shown in this device's zone, and words
// someone chose are shown exactly as they are. `terms`, by the type's `units`, say which currency an
// amount is in.
function readableRow(row, terms, units) {
  const label = row.field ? `${row.delivered ? "Delivered: " : ""}${fieldLabel(row.field).label}` : row.name;
  switch (row.shows) {
    case "type":
      return [label, typeName(row.shown)];
    case "number":
      return [label, fieldValue(row.field, row.shown, terms, units, row.delivered)];
    case "word":
      return [label, plainWord(row.shown)];
    case "times":
      return [label, row.times.map(when).join("\n")];
    case "earlier":
      return [label, "An earlier exchange"];
    default:
      return [label, row.shown];
  }
}

// What the type's fields say, every one of them, in plain words. Who it's with is the card's own
// heading, and the parties as signed, with their IDs, are in Exact terms with everything else.
function termsSummary(toSign) {
  const rows = toSign.rows.filter((row) => row.field || row.chosen || row.shows === "earlier");
  return el("div", { class: "summary" },
    el("p", { class: "summary-type" }, typeName(toSign.terms.type)),
    rows.length
      ? el("dl", { class: "summary-terms" }, ...rows.map((row) => {
          const [label, value] = readableRow(row, toSign.terms, toSign.units);
          const wide = row.chosen || row.times.length > 1;
          return el("div", { class: `${row.chosen ? "chosen" : ""}${wide ? " wide" : ""}` },
            el("dt", {}, label), el("dd", {}, el("span", {}, value)));
        }))
      : null);
}

// Who pays whom if this goes through, in fixed words code wrote from the type's `paid` and the signed
// terms. A field's name is whoever proposed the type's choice, so it never says which way money goes.
/** @param {string[]} lines */
function payingPart(lines) {
  return lines.length ? el("div", { class: "banner paying" }, ...lines.map((line) => el("p", {}, `${line}.`))) : null;
}

// Every term exactly as signed: names as the type has them, times in UTC, and the IDs.
function exactTerms(toSign) {
  return exact(
    ["Step", `${toSign.operation}, version ${toSign.version}`],
    ...toSign.rows.map((row) => [row.name, row.ids ? el("span", {}, row.shown, el("span", { class: "id" }, row.ids)) : row.shown]),
    ["Sign by", utc(toSign.sign_by)],
  );
}


// Characters that could hide what words say, as splint-core's is_hidden_character has them: controls,
// marks that draw as nothing, direction overrides, the tag block, variation selectors, private use and
// blank letters. Anything here is shown as its code, and a yes to words holding one is never asked for.
const HIDDEN = /[\p{Cc}\u00AD\u034F\u0600-\u0605\u061C\u06DD\u070F\u0890-\u0891\u08E2\u115F-\u1160\u17B4-\u17B5\u180B-\u180F\u200B-\u200F\u2028-\u202E\u2060-\u206F\u2800\u3164\uE000-\uF8FF\uFDD0-\uFDEF\uFE00-\uFE0F\uFEFF\uFFA0\uFFF0-\uFFFB\uFFFE-\uFFFF\u{110BD}\u{110CD}\u{13430}-\u{1343F}\u{1BCA0}-\u{1BCA3}\u{1D159}\u{1D173}-\u{1D17A}\u{E0000}-\u{E0FFF}\u{F0000}-\u{10FFFF}]/u;
const HIDDEN_ALL = new RegExp(HIDDEN.source, "gu");

function hasHiddenCharacters(text) {
  return HIDDEN.test(String(text));
}

// As Rust's char::escape_unicode writes one, so both pages show the same code.
function withHiddenShown(text) {
  return String(text).replace(HIDDEN_ALL, (found) => `\\u{${/** @type {number} */ (found.codePointAt(0)).toString(16)}}`);
}

// Whether terms hold words someone can't see all of, as Terms::hides_text has it. A Signet could put
// anything in any of these, so no yes is asked for, and no reader would take one.
function termsHideText(terms) {
  const inFields = (fields) => Object.entries(fields || {}).some(([name, value]) =>
    hasHiddenCharacters(name) || (typeof value === "string" && hasHiddenCharacters(value)));
  return inFields(terms.agreed) || inFields(terms.result)
    || (typeof terms.subject === "string" && hasHiddenCharacters(terms.subject))
    || (typeof terms.note === "string" && hasHiddenCharacters(terms.note));
}

// The rows of terms as signed, for a page with no schema to say what each value is, such as the owner
// page in a browser. So it guesses nothing a schema would say: a number is a number, unless `times`, the
// fields the agent's Signet says hold times, names it, a list is times, and any text is someone's words,
// shown exactly, with anything hidden shown as its code. `names` gives what the owner's own contacts
// call an ID, and nothing else names anyone.
/**
 * @typedef {{name: string, shown: string, ids: string | null, chosen: boolean, shows: string,
 *   field: string | null, delivered: boolean, times: number[]}} Row
 * @param {any} terms
 * @param {Map<string, string>} names
 * @param {string[]} [times]
 * @returns {Row[]}
 */
function rowsOf(terms, names, times) {
  /** @returns {Row} */
  const party = (side, which) => {
    const signed = terms[side] || {};
    const label = names.get(signed.agent) || "Someone who isn't in your contacts";
    return { name: which, shown: label, ids: `agent ${signed.agent}, owner ${signed.owner}`, chosen: false, shows: "party", field: null, delivered: false, times: [] };
  };
  /** @type {Row[]} */
  const rows = [
    { name: "type", shown: String(terms.type), ids: null, chosen: false, shows: "type", field: null, delivered: false, times: [] },
    party("requester", "Requester"),
    party("recipient", "Recipient"),
  ];
  /** @returns {Row[]} */
  const valueRows = (fields, delivered) => Object.entries(fields || {}).map(([name, value]) => {
    const shownName = withHiddenShown(name);
    if (Array.isArray(value)) {
      return { name: shownName, shown: value.map(utc).join(", "), ids: null, chosen: false, shows: "times", field: shownName, delivered, times: value };
    }
    if (typeof value === "number" && Number.isSafeInteger(value) && (times || []).includes(name)) {
      return { name: shownName, shown: `${utc(value)} (${value})`, ids: null, chosen: false, shows: "times", field: shownName, delivered, times: [value] };
    }
    if (typeof value === "number") {
      return { name: shownName, shown: String(value), ids: null, chosen: false, shows: "number", field: shownName, delivered, times: [] };
    }
    return { name: shownName, shown: withHiddenShown(value), ids: null, chosen: true, shows: "words", field: shownName, delivered, times: [] };
  });
  rows.push(...valueRows(terms.agreed, false), ...valueRows(terms.result, true));
  for (const [key, label] of [["subject", "Subject"], ["note", "Note"]]) {
    if (typeof terms[key] === "string") {
      rows.push({ name: label, shown: withHiddenShown(terms[key]), ids: null, chosen: true, shows: "words", field: null, delivered: false, times: [] });
    }
  }
  if (terms.supersedes) {
    rows.push({ name: "Replaces", shown: String(terms.supersedes), ids: null, chosen: false, shows: "earlier", field: null, delivered: false, times: [] });
  }
  return rows;
}

/**
 * The example kinds Splint ships, by ID, which keys_test.mjs holds to spec/schemas, so a kind of the
 * same name with another fingerprint reads as someone's own.
 */
const EXAMPLE_TYPES = [
  "meeting/1@i7fqx5fcz3sz4svkmv6ctjb2ksrzqknaho42n4nn7gz6qtuz2wqq",
  "quote/1@k6mkn6o2j7wes3mhauyvziyaoff3vsdhxarayv5zhongkruiavsa",
  "document/1@6hc5sgqdzhu66j6si3tpp5lqkqbhbdccgditkmdotswxix3h6tpq",
  "rsvp/1@z66jzod2xin67ozi6zz2s7x57qhnfzanlgb7ubeytajekmookbdq",
  "time/1@kywplefbukn3savbqlp7w7lkx2pvpjjnnrd4ocm72amdxhynqbrq",
];

/** Characters of a fingerprint shown to a person, as core shows them. */
const SHORT_FINGERPRINT_CHARS = 8;

/** A side, as a person reads which one a kind's money is paid to, as core says it. */
const SIDE_WORDS = { requester: "whoever opens it", recipient: "whoever it's opened with" };

/** What fits one field, in core's fixed words around the kind's own words and numbers. @param {any} rule */
function ruleInWords(rule) {
  if (Array.isArray(rule.word)) return `one of ${[...rule.word].sort().join(", ")}`;
  if (Array.isArray(rule.one_of)) return `a number, one of ${[...rule.one_of].sort((a, b) => a - b).join(", ")}`;
  if (rule.range) return `a number from ${rule.range.min} to ${rule.range.max}`;
  if (rule.times) {
    const grid = rule.times.grid_secs % 60 === 0 ? `${rule.times.grid_secs / 60}-minute` : `${rule.times.grid_secs}-second`;
    return `up to ${rule.times.max} times, on a ${grid} grid`;
  }
  if (rule.text) return `words someone chose, up to ${rule.text.max_chars} characters`;
  return "something this page doesn't know";
}

/**
 * A kind as its owner is asked to approve it, line by line in core's fixed words, the same lines
 * `requests::for_approval` writes: what it is and whose, each field, its money and whom that's paid
 * to, and who signs. `id` is the ID this page worked out from the schema, and `agreed` every kind's ID
 * the agent agreed, which a lookalike is named after.
 * @param {any} schema @param {string} id @param {string[]} agreed
 * @returns {{lines: string[], includesCurrency: boolean, sameName: string | null}}
 */
function kindLines(schema, id, agreed) {
  const [name, fingerprint = ""] = id.split("@");
  const short = (one) => (one.split("@")[1] || "").slice(0, SHORT_FINGERPRINT_CHARS);
  const mine = short(id);
  const example = EXAMPLE_TYPES.find((one) => one.split("@")[0] === name);
  const other = agreed.find((one) => one.split("@")[0] === name && one !== id);
  /** @type {"the_example" | "like_an_example" | "like_another_agreed" | null} */
  let sameName = null;
  let first = `${name}, fingerprint ${mine}.`;
  if (example === id) {
    sameName = "the_example";
    first = `${name}, fingerprint ${mine}: the same as the example Splint ships.`;
  } else if (example) {
    sameName = "like_an_example";
    first = `${name}, fingerprint ${mine}: their own kind, not the example Splint ships, whose fingerprint is ${short(example)}.`;
  } else if (other) {
    sameName = "like_another_agreed";
    first = `${name}, fingerprint ${mine}: their own kind, not the ${name} agreed with someone else, whose fingerprint is ${short(other)}.`;
  }
  const paid = schema.paid || {};
  const units = schema.units || {};
  const fixed = new Set(schema.fixed || []);
  const sorted = (fields) => Object.keys(fields || {}).sort().map((field) => [field, fields[field]]);
  const field = (section, field, rule) => {
    let line = `${section} ${field}: ${ruleInWords(rule)}`;
    const number = Boolean(rule.range || rule.one_of);
    if (number && paid[field]) {
      line += `, money paid to ${SIDE_WORDS[paid[field]] || paid[field]}`;
      if (units[field]) line += `, in the unit ${units[field]} names`;
    } else if (number) {
      line += ", a number not labelled as money";
    }
    if (fixed.has(field)) line += ", set when it's opened";
    return line;
  };
  const lines = [first];
  for (const [one, rule] of sorted(schema.offer)) lines.push(field("Offer", one, rule));
  for (const [one, from] of sorted(schema.pick)) lines.push(`Accept picks ${one}: one time from ${from}`);
  for (const [one, rule] of sorted(schema.result)) lines.push(field("Result", one, rule));
  for (const [one, rule] of sorted(schema.say)) lines.push(field("Says", one, rule));
  lines.push({ requester: "The owner of whoever opens it signs before it's done", both: "Both owners sign before it's done" }[schema.sign] || "No owner signs it before it's done");
  const includesCurrency = Object.keys(paid).length > 0;
  if (includesCurrency) {
    lines.push("It has money, so your agent uses it only once you approve it, and agreeing an amount waits for you as any price does.");
  }
  return { lines: fingerprint ? lines : [first], includesCurrency, sameName };
}
