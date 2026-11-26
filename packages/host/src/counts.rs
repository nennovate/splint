//! `splint-host counts`: how many agents, owners and other hosts use this host, for whoever runs it.
//!
//! Each figure is an exact count under a fixed label, read in one `READ ONLY` transaction from what
//! the host already keeps. It never prints an ID, handle, address, domain or anything an agent wrote,
//! never opens a stored envelope, and calls out to nothing, so what it prints stays with the operator.
//! A figure drawn from a table the host caps or prunes is a lower bound, as `docs/run-a-host.md` says.

use sqlx::{PgPool, Row};

/// Every label, in the order printed. Each is a column of `COUNTS` by the same name.
const LABELS: [&str; 15] = [
    "agents",
    "stand_ins",
    "revoked",
    "open_signup",
    "owners",
    "new_agents_1d",
    "new_agents_7d",
    "new_agents_30d",
    "texts_24h",
    "requests_24h",
    "sent_out_7d",
    "sent_out_30d",
    "other_hosts",
    "remote_agents",
    "remote_owners",
];

// `texts` and `new_requests` keep unix seconds, and each message is a row for each local agent it
// touches, so one text between two agents here is two rows of one message. A peer is remote when no
// agent here has its ID, retired ones included, as they keep their rows.
const COUNTS: &str = "
    WITH now_secs AS (SELECT extract(epoch FROM now())::bigint AS at),
    peers AS (
        SELECT peer FROM met
        UNION SELECT peer FROM reached
        UNION SELECT sender FROM inbox WHERE sender <> ''
    )
    SELECT
        (SELECT count(*) FROM agents WHERE retirement IS NULL) AS agents,
        (SELECT count(*) FROM agents WHERE retirement IS NULL AND stand_in) AS stand_ins,
        (SELECT count(*) FROM agents WHERE retirement IS NULL AND revocation IS NOT NULL)
            AS revoked,
        (SELECT count(*) FROM agents WHERE retirement IS NULL AND open_source IS NOT NULL)
            AS open_signup,
        (SELECT count(DISTINCT owner_id) FROM agents WHERE retirement IS NULL AND NOT stand_in)
            AS owners,
        (SELECT count(*) FROM agents WHERE created_at > now() - interval '1 day') AS new_agents_1d,
        (SELECT count(*) FROM agents WHERE created_at > now() - interval '7 days') AS new_agents_7d,
        (SELECT count(*) FROM agents WHERE created_at > now() - interval '30 days')
            AS new_agents_30d,
        (SELECT count(DISTINCT message_id) FROM texts, now_secs WHERE texts.at > now_secs.at - 86400)
            AS texts_24h,
        (SELECT count(DISTINCT message_id) FROM new_requests, now_secs
            WHERE new_requests.at > now_secs.at - 86400) AS requests_24h,
        (SELECT count(DISTINCT agent) FROM hosts_sent_to WHERE at > now() - interval '7 days')
            AS sent_out_7d,
        (SELECT count(DISTINCT agent) FROM hosts_sent_to WHERE at > now() - interval '30 days')
            AS sent_out_30d,
        (SELECT count(*) FROM (SELECT domain FROM peer_keys UNION SELECT host FROM hosts_sent_to)
            AS hosts) AS other_hosts,
        (SELECT count(*) FROM peers WHERE peer NOT IN (SELECT id FROM agents)) AS remote_agents,
        (SELECT count(DISTINCT owner) FROM reached WHERE peer NOT IN (SELECT id FROM agents))
            AS remote_owners
";

/// Each label and its count, one a line, from one snapshot of the database.
pub async fn lines(db: &PgPool) -> Result<String, sqlx::Error> {
    let mut reading = crate::database::begin(db).await?;
    sqlx::query("SET TRANSACTION READ ONLY")
        .execute(&mut *reading)
        .await?;
    let row = sqlx::query(COUNTS).fetch_one(&mut *reading).await?;
    reading.commit().await?;
    let mut lines = Vec::with_capacity(LABELS.len());
    for label in LABELS {
        let count: i64 = row.try_get(label)?;
        lines.push(format!("{label:<15} {count}"));
    }
    Ok(lines.join("\n"))
}
