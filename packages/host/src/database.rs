//! Connects to Postgres, refusing any connection where queued mail could be read on the way, and opens
//! transactions so that a caller hanging up can't leave one open.

use std::str::FromStr;
use std::time::Duration;

use splint_core::transport::{Scheme, is_loopback};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::{PgPool, Postgres, Transaction};
use tokio::sync::Semaphore;

pub const SETTING: &str = "SPLINT_DATABASE_URL";
const MAX_CONNECTIONS: u32 = 10;
/// One place for each connection, as no more than that can be opening at once anyway. Whoever hangs up
/// while waiting for a place costs nothing, so a flood of hang-ups leaves at most this many behind.
static OPENING: Semaphore = Semaphore::const_new(MAX_CONNECTIONS as usize);
/// How long a host waits for a connection, at its start and on each call after. A database that's
/// still starting gets this long.
pub const HOST_PATIENCE: Duration = Duration::from_secs(30);
/// How long a one-shot waits, with someone at a terminal waiting on it.
pub const ONE_SHOT_PATIENCE: Duration = Duration::from_secs(5);

/// What's wrong with the database setting. The address is never repeated, as it can hold a password.
#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error(
        "{SETTING} isn't a Postgres address, such as postgres:///splint?host=/var/run/postgresql"
    )]
    NotAnAddress,
    #[error(
        "{SETTING} has to name a database on a local socket, on this machine, or reached with \
         sslmode=verify-full"
    )]
    Unsafe,
    #[error("couldn't reach the database {SETTING} names: {0}")]
    Unreachable(sqlx::Error),
}

/// A test setup that already talks plain HTTP only to names that can't leave the machine may reach
/// its database by such a name too, as a container network does. A real server's scheme is HTTPS.
fn crosses_a_network_unprotected(options: &PgConnectOptions, scheme: Scheme) -> bool {
    let local = options.get_socket().is_some()
        || is_loopback(options.get_host())
        || (!scheme.is_https() && scheme.check_destination(options.get_host()).is_ok());
    !local && !matches!(options.get_ssl_mode(), PgSslMode::VerifyFull)
}

pub async fn connect(
    url: &str,
    scheme: Scheme,
    patience: Duration,
) -> Result<PgPool, DatabaseError> {
    let options = PgConnectOptions::from_str(url).map_err(|_| DatabaseError::NotAnAddress)?;
    if crosses_a_network_unprotected(&options, scheme) {
        return Err(DatabaseError::Unsafe);
    }
    // Postgres says so each time a table a start makes is already there, which is every table on
    // every start but the first, and whoever reads the log needs what follows.
    let options = options.options([("client_min_messages", "warning")]);
    PgPoolOptions::new()
        .max_connections(MAX_CONNECTIONS)
        .acquire_timeout(patience)
        .connect_with(options)
        .await
        .map_err(DatabaseError::Unreachable)
}

/// Opens a transaction, the only way this host does. sqlx sends `BEGIN` and only counts the transaction
/// as open once Postgres answers, so a caller dropped in between, as hyper drops a handler whose client
/// hung up, hands the connection back still inside it. Every later write on that connection would be
/// answered as saved and lost when the connection closed. So `BEGIN` runs on a task of its own that a
/// caller can't cancel, and a transaction nobody is left to take is dropped there, which rolls it back.
pub async fn begin(pool: &PgPool) -> Result<Transaction<'static, Postgres>, sqlx::Error> {
    let opened = async {
        let place = OPENING
            .acquire()
            .await
            .map_err(|_| sqlx::Error::PoolClosed)?;
        let pool = pool.clone();
        tokio::spawn(async move {
            let _place = place;
            #[expect(
                clippy::disallowed_methods,
                reason = "this is the one place that may, on a task no caller can cancel"
            )]
            pool.begin().await
        })
        .await
        .map_err(|_| sqlx::Error::WorkerCrashed)?
    };
    // However long the queue for a place, a caller waits no longer than for a connection.
    tokio::time::timeout(pool.options().get_acquire_timeout(), opened)
        .await
        .map_err(|_| sqlx::Error::PoolTimedOut)?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unprotected(url: &str) -> bool {
        crosses_a_network_unprotected(&PgConnectOptions::from_str(url).unwrap(), Scheme::Https)
    }

    #[test]
    fn only_a_local_database_or_verified_tls_is_allowed() {
        for fine in [
            "postgres:///splint?host=/var/run/postgresql&user=splint",
            "postgres://splint:pw@127.0.0.1:5432/splint",
            "postgres://splint:pw@localhost:5432/splint",
            "postgres://splint:pw@[::1]:5432/splint",
            "postgres://splint:pw@db.example:5432/splint?sslmode=verify-full",
        ] {
            assert!(!unprotected(fine), "{fine}");
        }
        for refused in [
            "postgres://splint:pw@db.example:5432/splint",
            "postgres://splint:pw@db.example:5432/splint?sslmode=disable",
            "postgres://splint:pw@db.example:5432/splint?sslmode=prefer",
            "postgres://splint:pw@db.example:5432/splint?sslmode=require",
            "postgres://splint:pw@db.example:5432/splint?sslmode=verify-ca",
            "postgres://splint:pw@10.0.0.5:5432/splint?sslmode=require",
        ] {
            assert!(unprotected(refused), "{refused}");
        }
    }

    #[test]
    fn a_plain_test_setup_reaches_only_a_database_that_stays_on_its_network() {
        let plain = |url: &str| {
            crosses_a_network_unprotected(
                &PgConnectOptions::from_str(url).unwrap(),
                Scheme::PlainHttpForTests,
            )
        };
        assert!(!plain("postgres://postgres@pg-a/postgres"));
        assert!(!plain("postgres://postgres@db.test/postgres"));
        assert!(unprotected("postgres://postgres@pg-a/postgres"));
        for refused in [
            "postgres://postgres@db.example/postgres",
            "postgres://postgres@10.0.0.5/postgres",
        ] {
            assert!(plain(refused), "{refused}");
        }
    }
}
