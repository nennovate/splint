// The page Splint on this computer serves at /ask. An agent's link carries one ask it signed after the
// `#`, which any website can open, so this hands it to Splint here only once the person clicks to see
// it, then shows it in the fixed words its prompt names it by, which the owner key writes from what it
// signs, with any words an agent wrote apart and marked, and approves exactly that ask on a second
// click. Opened from the person's controls, it lists the asks the next approval signs, as Splint here
// groups them by the prompt's rule, with its code, and approves exactly those shown with that code.
// Once the person starts typing their passphrase, a refresh no longer changes what's listed or what
// Approve sends: an ask that comes in meanwhile is only said to be there, and waits for an approval of
// its own. Approving, and seeing what waits, need the page key, which only a page the person opened
// with `splint controls` holds.

// Its own scope, as the page check reads every page script together.
(() => {
  /** Where the owner page here keeps the page key, which this page shares as it's the same origin. */
  const PAGE_KEY = "splint-page-key";

  /** @returns {string} */
  function pageKey() {
    try {
      return localStorage.getItem(PAGE_KEY) || "";
    } catch {
      return "";
    }
  }

  /** @param {string} text */
  function el(text) {
    const item = document.createElement("li");
    item.textContent = text;
    return item;
  }

  /** @param {string} path @param {object} [body] */
  async function call(path, body) {
    /** @type {Record<string, string>} */
    const headers = { "Content-Type": "application/json" };
    const key = pageKey();
    if (key) headers["Splint-Page"] = key;
    const answer = await fetch(path, body
      ? { method: "POST", headers, body: JSON.stringify(body), credentials: "omit" }
      : { headers, credentials: "omit" });
    const read = await answer.json().catch(() => ({}));
    if (answer.status === 403) throw new Error(NO_KEY);
    if (!answer.ok) throw new Error(typeof read.error === "string" ? read.error : "Splint here didn't answer.");
    return read;
  }

  const NO_KEY = "To approve here, open your controls on this computer with splint controls HOST in a terminal, then this page again. Or approve in a terminal with splint computer approve.";

  const said = /** @type {HTMLElement} */ (document.getElementById("said"));
  // What the last Approve came to. show() rewrites #said right after, so this keeps its own line.
  const outcome = /** @type {HTMLElement} */ (document.getElementById("outcome"));
  const list = /** @type {HTMLElement} */ (document.getElementById("asks"));
  const after = /** @type {HTMLElement} */ (document.getElementById("later"));
  const row = /** @type {HTMLElement} */ (document.getElementById("approve-row"));
  const passRow = /** @type {HTMLElement} */ (document.getElementById("passphrase-row"));
  const pass = /** @type {HTMLInputElement} */ (document.getElementById("passphrase"));
  const passLabel = /** @type {HTMLElement} */ (document.getElementById("passphrase-label"));
  const againRow = /** @type {HTMLElement} */ (document.getElementById("passphrase-again-row"));
  const again = /** @type {HTMLInputElement} */ (document.getElementById("passphrase-again"));
  const whyNew = /** @type {HTMLElement} */ (document.getElementById("new-passphrase-why"));
  const plain = /** @type {HTMLElement} */ (document.getElementById("plain-key-file"));
  /** The fewest characters a key file's passphrase has, as the owner key holds one to. */
  const FEWEST_PASSPHRASE_CHARACTERS = 8;
  const button = /** @type {HTMLButtonElement} */ (document.getElementById("approve"));
  const passOn = /** @type {HTMLElement} */ (document.getElementById("pass-on"));

  /**
   * Answers an agent's host didn't keep, such as a host from before answers were kept where an ask
   * says, for the person to give that agent, as nothing else reaches one elsewhere.
   * @param {{address: string, answer: string}[]} unkept
   */
  function showPassOn(unkept) {
    passOn.replaceChildren(...unkept.flatMap((one) => {
      const words = document.createElement("p");
      words.textContent = `${one.address}'s host didn't keep your answer, so it can't take it up from there. Send it this line, all of it:`;
      const line = document.createElement("pre");
      line.className = "code";
      line.textContent = `splint finish ${one.answer}`;
      return [words, line];
    }));
    passOn.hidden = !unkept.length;
  }

  /** The IDs of the asks the person sees now, which an approval signs and nothing else. @type {string[]} */
  let shownIds = [];
  /** The code shown with them, which Splint here checks is theirs before anything is signed. @type {string | null} */
  let shownCode = null;
  /** Whether the person has started approving what's listed, so a refresh leaves it as it is. */
  let begun = false;
  /** The link's ask, once the person clicked to see it: the page then shows and approves it alone. @type {any} */
  let linked = null;
  /** Whether a link's ask waits for the person's click to see it, which nothing else replaces. */
  let offering = false;
  /** Whether this approval makes the sign-in here, a key file locked with a passphrase chosen now. */
  let making = false;
  /** Whether the next listing follows an Approve, whose outcome is about the asks that listing drops. */
  let keepOutcome = false;

  /**
   * Each ask in the words its prompt names it by, which Splint here had the owner key write from what
   * it signs, so this page says no less than the prompt: for a held step, who pays whom and how much,
   * who it's with and its terms; for a contact, the agent ID signed and whether their words come in.
   * The changes are listed under the agent that asked, each agent once in the order its first ask
   * came, so a person reads them as that agent's request, however many asks it made. What an agent
   * wrote in a held step comes last, marked as theirs, and the warning when it lets more in.
   * @param {any[]} asks
   */
  function showAsks(asks) {
    const written = asks.flatMap((/** @type {any} */ ask) => Array.isArray(ask.written) ? ask.written : []);
    /** @type {Map<string, any[]>} */
    const byAgent = new Map();
    for (const ask of asks) byAgent.set(ask.address, [...(byAgent.get(ask.address) || []), ask]);
    list.replaceChildren(...[...byAgent].map(([address, theirs]) => {
      const item = el(`${address} asks you to:`);
      const changes = document.createElement("ul");
      changes.replaceChildren(...theirs.flatMap((/** @type {any} */ ask) => [
        ...(Array.isArray(ask.said) ? ask.said : []).map((/** @type {string} */ said) => el(said)),
        // What each type named holds, in core's fixed words, worked out by Splint here from its schema.
        ...(ask.kinds || []).flatMap((/** @type {any} */ kind) => (kind.lines || []).map((/** @type {string} */ line) => el(line))),
        ...(ask.from_link ? [el(`That came by a link, which any website can open: approve it only if you asked ${ask.address}.`)] : []),
      ]));
      item.append(changes);
      return item;
    }),
    ...(written.length ? [el(`Words from the request, not Splint's: ${written.join(", ")}`)] : []),
    ...(asks.some((/** @type {any} */ ask) => ask.lets_more_in)
      ? [warned("This lets more in than before. Only approve it if you asked for it, or it's what you want.")] : []));
    shownIds = asks.map((/** @type {any} */ ask) => ask.id);
  }

  /** How many changes these asks hold, as Approve signs them, however many agents asked. @param {any[]} asks */
  function changesIn(asks) {
    return asks.reduce((count, /** @type {any} */ ask) => count + (Array.isArray(ask.changes) ? ask.changes.length : 0), 0);
  }

  /**
   * What these asks hold, as a person reads it: a held step is a step to send, not a change to a rule,
   * so it's named a step, and one is alone in its approval.
   * @param {any[]} asks
   */
  function nounFor(asks) {
    const changes = asks.flatMap((/** @type {any} */ ask) => Array.isArray(ask.changes) ? ask.changes : []);
    const steps = changes.length > 0 && changes.every((/** @type {any} */ change) => change.change === "step");
    return changes.length === 1 ? (steps ? "this step" : "this change") : (steps ? "these steps" : "these changes");
  }

  /**
   * What approving does, in plain words, as a person can take a passphrase box for a sign-in. An agent
   * asking for controls isn't theirs until they approve, so it isn't called theirs.
   * @param {any[]} asks @param {boolean} touch @param {boolean} making
   */
  function introFor(asks, touch, making) {
    const noun = nounFor(asks);
    const one = changesIn(asks) === 1;
    const agents = new Set(asks.map((/** @type {any} */ ask) => ask.address)).size;
    const controls = asks.some((/** @type {any} */ ask) =>
      (Array.isArray(ask.changes) ? ask.changes : []).some((/** @type {any} */ change) => change.change === "controls"));
    const who = agents === 1 ? (controls ? "An agent" : "Your agent") : (controls ? "These agents" : "Your agents");
    const how = touch ? `: your Mac asks for Touch ID or your password, naming exactly ${noun}` : "";
    const setUp = making ? ", and sets up your sign-in here" : "";
    return `${who} asked for ${noun}. Approving signs ${one ? "it" : "them"} with your owner key on this computer${how}${setUp}. `
      + "It doesn't log you in to a website or account.";
  }

  /** @param {string} text */
  function warned(text) {
    const item = el(text);
    item.className = "warn";
    return item;
  }

  for (const typed of [pass, again]) {
    typed.addEventListener("focus", () => { begun = true; });
    typed.addEventListener("input", () => { begun = true; });
  }

  /** @param {string[]} ids */
  function sameAsShown(ids) {
    return ids.length === shownIds.length && ids.every((id, at) => id === shownIds[at]);
  }

  async function show() {
    const keep = keepOutcome;
    keepOutcome = false;
    if (!pageKey()) {
      if (linked) showAsks([linked]);
      said.textContent = NO_KEY;
      row.hidden = true;
      return;
    }
    const [waiting, here] = await Promise.all([call("/local/asks"), call("/local/here")]);
    // Each approval's worth, as Splint here groups them: the next first, then those after it.
    const approvals = [{ asks: waiting.asks, code: waiting.code }, ...(waiting.later || [])]
      .filter((/** @type {any} */ one) => one.asks && one.asks.length);
    const next = linked
      ? approvals.find((/** @type {any} */ one) => one.asks.some((/** @type {any} */ ask) => ask.id === linked.id))
      : approvals[0];
    const asks = next ? next.asks : [];
    const ids = asks.map((/** @type {any} */ ask) => ask.id);
    // The person is reading and typing for what's listed, so it stays as it is, and so does what
    // Approve sends: anything new waits for its own approval.
    if (begun && shownIds.length) {
      after.textContent = sameAsShown(ids)
        ? ""
        : "What's waiting changed since this was listed. Approve signs only what's listed here, and anything new waits for its own approval.";
      return;
    }
    // An outcome stays only until another set of asks is listed, so it isn't read as about those.
    if (!keep && !sameAsShown(ids)) outcome.textContent = "";
    showAsks(asks);
    plain.hidden = !(here.here || {}).plain_key_file;
    whyNew.hidden = true;
    shownCode = next ? next.code : null;
    const more = linked ? 0 : approvals.length - 1;
    after.textContent = more ? `${more} more ${more === 1 ? "approval waits" : "approvals wait"} after this one, each shown before it's signed.` : "";
    if (!asks.length) {
      said.textContent = linked ? "That ask isn't waiting any more." : "Nothing is waiting for you.";
      row.hidden = true;
      return;
    }
    const held = (here.here || {}).sign_in;
    // Off the chip, the first approval makes the sign-in, a key file locked with a passphrase chosen here.
    making = !held && !waiting.prompts_by_itself;
    said.textContent = introFor(asks, !!waiting.prompts_by_itself, making);
    const count = changesIn(asks);
    const noun = nounFor(asks);
    button.textContent = count === 1 ? `Approve ${noun}` : `Approve ${noun.replace("these ", `these ${count} `)}`;
    row.hidden = false;
    passRow.hidden = !(making || String(held || "").includes("passphrase"));
    passLabel.textContent = making ? "Choose a passphrase" : "Your owner passphrase, to sign this approval";
    againRow.hidden = !making;
    whyNew.hidden = !making;
  }

  button.addEventListener("click", async () => {
    button.disabled = true;
    outcome.textContent = "";
    try {
      if (making && [...pass.value].length < FEWEST_PASSPHRASE_CHARACTERS) {
        throw new Error(`A passphrase has at least ${FEWEST_PASSPHRASE_CHARACTERS} characters, so nothing was signed.`);
      }
      if (making && pass.value !== again.value) throw new Error("Those two passphrases aren't the same, so nothing was signed.");
      const done = await call("/local/approve", { passphrase: pass.value || null, ids: shownIds, code: shownCode });
      outcome.textContent = done.approved ? "Approved. Your agents hear it from their hosts." : "Nothing was approved.";
      showPassOn(Array.isArray(done.pass_on) ? done.pass_on : []);
    } catch (error) {
      outcome.textContent = error.message;
    } finally {
      pass.value = "";
      again.value = "";
      begun = false;
      button.disabled = false;
      keepOutcome = true;
      await show().catch(() => {});
    }
  });

  /** A link's ask, shown with a button to see it, as opening a link is all a website can do. @param {string} ask @param {string} address */
  function offer(ask, address) {
    offering = true;
    said.textContent = "An agent's link asks you for changes on this computer.";
    const see = document.createElement("button");
    see.type = "button";
    see.textContent = "See what it asks";
    see.addEventListener("click", async () => {
      see.disabled = true;
      try {
        const taken = await call("/local/asks", { ask, address });
        if (!taken.ask) throw new Error("That ask isn't waiting here.");
        linked = taken.ask;
        offering = false;
        see.remove();
        await show();
      } catch (error) {
        said.textContent = error.message;
        see.disabled = false;
      }
    });
    list.replaceChildren(see);
  }

  function start() {
    const fragment = new URLSearchParams(location.hash.slice(1));
    const ask = fragment.get("ask");
    const address = fragment.get("at");
    history.replaceState(null, "", location.pathname);
    if (ask && address) {
      offer(ask, address);
      return;
    }
    show().catch((error) => { said.textContent = error.message; });
  }

  start();
  setInterval(() => { if (!offering) show().catch(() => {}); }, 5000);
})();
