//! `splint guide`: the parts of `docs/how-it-works.md` an owner or agent reads to understand Splint,
//! from the copy built into this program. So it's there offline, it's the release's own words rather
//! than any host's, and `splint verify` checks it along with the program.

use splint_core::release::REPOSITORY;

use crate::failure::Failure;

const HOW_IT_WORKS: &str = include_str!("../../../docs/how-it-works.md");

/// Each topic is a heading in `docs/how-it-works.md`, and runs to the next heading as high as its own.
const TOPICS: [(&str, &str, &str); 5] = [
    (
        "about",
        "## In plain words",
        "What Splint is and isn't, and what an owner decides",
    ),
    (
        "sealed",
        "### Sealed and unsealed",
        "Sealed or unsealed, and what each gives up",
    ),
    (
        "joining",
        "## Joining and setting up your controls",
        "Joining, and setting up your controls",
    ),
    (
        "types",
        "### Agreeing a type in conversation",
        "How two agents agree a kind of request, and what holds it",
    ),
    (
        "safety",
        "## Safety in plain words",
        "What's protected, and the honest limits",
    ),
];

pub fn guide(topic: Option<&str>) -> Result<String, Failure> {
    match topic {
        None => Ok(listing()),
        Some("all") => Ok(without_diagrams(HOW_IT_WORKS.lines()).join("\n")),
        Some(word) => TOPICS
            .iter()
            .find(|(name, _, _)| *name == word)
            .and_then(|(_, heading, _)| section(heading))
            .ok_or_else(|| {
                Failure::refused(format!(
                    "there's no topic {word}: run splint guide for the list"
                ))
            }),
    }
}

fn listing() -> String {
    let mut lines = vec![
        "splint guide TOPIC, from the copy built into this release:".to_owned(),
        String::new(),
    ];
    for (name, _, about) in TOPICS {
        lines.push(format!("  {name:<10}{about}"));
    }
    lines.push(format!("  {:<10}All of how Splint works", "all"));
    lines.push(String::new());
    lines.push(format!(
        "The same, with diagrams, is at https://github.com/{REPOSITORY}/blob/main/docs/how-it-works.md"
    ));
    lines.join("\n")
}

fn section(heading: &str) -> Option<String> {
    let level = heading_level(heading)?;
    let mut lines = HOW_IT_WORKS.lines().skip_while(|line| *line != heading);
    let first = lines.next()?;
    let mut fenced = false;
    let rest = lines.take_while(|line| {
        if line.starts_with("```") {
            fenced = !fenced;
        }
        fenced || heading_level(line).is_none_or(|own| own > level)
    });
    let kept = without_diagrams(std::iter::once(first).chain(rest));
    Some(kept.join("\n").trim_end().to_owned())
}

fn heading_level(line: &str) -> Option<usize> {
    let hashes = line.chars().take_while(|c| *c == '#').count();
    (hashes > 0 && line.chars().nth(hashes) == Some(' ')).then_some(hashes)
}

/// A terminal can't draw a diagram, and every one sits beside words that say the same.
fn without_diagrams<'a>(lines: impl Iterator<Item = &'a str>) -> Vec<&'a str> {
    let mut in_diagram = false;
    let mut kept = Vec::new();
    for line in lines {
        if line == "```mermaid" {
            in_diagram = true;
        } else if in_diagram {
            in_diagram = line != "```";
        } else if !(line.is_empty() && kept.last().is_some_and(|last: &&str| last.is_empty())) {
            kept.push(line);
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_topic_is_a_heading_in_the_doc_and_stops_at_the_next_one_as_high() {
        for (name, heading, _) in TOPICS {
            let text = guide(Some(name)).expect(name);
            assert!(text.starts_with(heading), "{name}");
            assert!(text.lines().count() > 3, "{name} is nearly empty");
            let level = heading_level(heading).expect(name);
            let higher = text
                .lines()
                .skip(1)
                .filter_map(heading_level)
                .any(|own| own <= level);
            assert!(!higher, "{name} runs into the next section");
            assert!(!text.contains("```mermaid"), "{name} keeps a diagram");
        }
    }
}
