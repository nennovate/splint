#!/usr/bin/env python3
"""Measures what a test server can carry, driving it from outside the container.

Docker on a busy laptop isn't a small server, so a number here shows how the host behaves and where
it stops, not what a real machine would do. Every scenario writes one JSON line per step to --out.
"""

import argparse
import json
import multiprocessing
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from dataclasses import replace
from pathlib import Path
from statistics import median

import driver
from driver import WORKERS, Load
from server_probe import ServerProbe, cpu_cores, throttled_share
from signing import Agent, b64

HERE = Path(__file__).resolve().parent
TEST_SERVER = HERE.parent / "test-server"
PACKAGES = HERE.parent.parent / "packages"
PORTS = {"small": 18180, "tiny": 18190}
SECONDS_PER_DAY = 86400
PEAK_FACTOR = 10
P95_LIMIT_S = 0.5
ERROR_LIMIT = 0.001
# A step fails when messages are waiting for longer than this at its end.
BACKLOG_LIMIT_SECONDS = 5
MIN_FREE_DOCKER_GB = 5
START_ATTEMPTS = 4


class Server:
    def __init__(self, name: str, port: int, profile: str, peers: str = "", image: str = "splint-test-server",
                 nofile: int | None = None):
        self.name, self.port, self.profile, self.peers, self.image, self.nofile = name, port, profile, peers, image, nofile
        self.domain = f"{name}:8080"
        self.url = f"http://127.0.0.1:{port}"
        self.probe = ServerProbe(name)
        self.start()

    def start(self) -> None:
        command = [sys.executable, str(TEST_SERVER / "server.py"), "start", self.profile, "--no-build", "--name", self.name,
                   "--port", str(self.port), "--image", self.image]
        if self.nofile:
            command += ["--nofile", str(self.nofile)]
        # Parallel runs share a Docker network, and one stopping can remove it as another starts.
        for attempt in range(START_ATTEMPTS):
            done = subprocess.run(command, capture_output=True, text=True)
            if done.returncode == 0:
                return
            time.sleep(2)
        raise RuntimeError(f"{self.name} didn't start: {done.stderr[-400:]}")

    def stop(self) -> None:
        subprocess.run([sys.executable, str(TEST_SERVER / "server.py"), "stop", "--name", self.name], capture_output=True)


class Run:
    """What every scenario shares: the driver processes and where results go."""

    def __init__(self, pool, out: Path, profile: str, image: str):
        self.pool, self.out, self.profile, self.image = pool, out, profile, image
        self.seed = driver.random.randbytes(4).hex()
        self.registered = {}

    def server(self, suffix: str = "", peers: str = "", **options) -> Server:
        offset = {"": 0, "-b": 1, "-c": 2}[suffix]
        return Server(f"splint-test-load-{self.profile}{suffix}", PORTS[self.profile] + offset, self.profile,
                      peers, options.pop("image", self.image), **options)

    def record(self, scenario: str, row: dict) -> dict:
        row = {"scenario": scenario, "profile": self.profile, "image": self.image, "at": int(time.time()), **row}
        with self.out.open("a") as file:
            file.write(json.dumps(row) + "\n")
        print(json.dumps(row), flush=True)
        return row

    def register(self, server: Server, owners: int) -> None:
        """Puts agents straight in the database, past the limits a host puts on new agents, each with its
        owner's binding and rules. An even number, because owners set each other up in pairs."""
        owners += owners % 2
        done = self.registered.get(server.name, 0)
        if owners <= done:
            return
        size = max((owners - done) // (WORKERS * 4), 2)
        size += size % 2
        partner_domain = server.peers or server.domain
        chunks = [(self.seed, i, min(i + size, owners), server.domain, partner_domain) for i in range(done, owners, size)]
        rows = [row for chunk in self.pool.imap(driver.agent_rows, chunks) for row in chunk]
        for table, written in (("agents (id, handle, identity, owner_id, owner_identity, binding, binding_seq)", 0), ("rules (agent, seq, compact)", 1)):
            server.probe.exec("psql", "-U", "postgres", "-c", f"COPY {table} FROM STDIN",
                              input="".join(row[written] + "\n" for row in rows), check=True)
        server.probe.sql("ANALYZE agents")
        server.probe.sql("ANALYZE rules")
        self.registered[server.name] = owners

    def step(self, server: Server, load: Load, others: tuple = ()) -> dict:
        """Runs one load step and reads the server's counters over exactly the time it ran."""
        load = replace(load, start_at=time.time() + 1.5)
        delivered_before = delivered(server)
        waiting = self.pool.map_async(driver.run_worker, [(load, i) for i in range(WORKERS)])
        time.sleep(max(load.start_at - time.time(), 0))
        before = server.probe.cgroup()
        others_before = [other.probe.cgroup() for other in others]
        time.sleep(load.seconds)
        after = server.probe.cgroup()
        others_after = [other.probe.cgroup() for other in others]
        pending = server.probe.scalar("SELECT count(*) FROM outbound WHERE status = 'pending'")
        delivered_after = delivered(server)
        merged = driver.merge(waiting.get())
        row = {
            "owners": load.owners, "seconds": load.seconds, "target_rates": load.rates, "kinds": {},
            "errors": {k: v for k, v in merged["outcomes"].items() if not k.endswith(":200")},
            "cpu_cores": round(cpu_cores(before, after), 2), "throttled": round(throttled_share(before, after), 2),
            "memory_mb": round(after.get("memory_current", 0) / 1e6), "anon_mb": round(after.get("anon", 0) / 1e6),
            "host_rss_mb": round(after.get("host_rss_kb", 0) / 1e3), "host_fds": after.get("host_fds"),
            "oom_kills": after.get("oom_kill", 0), "pending_at_end": pending,
            "delivered_per_s": round((delivered_after - delivered_before) / (after["at"] - before["at"]), 1),
            "driver_lag_p95_ms": round(merged["lag_p95_ms"], 1), "alive": server.probe.alive(),
        }
        total = 0
        for kind, values in merged["latencies"].items():
            total += len(values)
            row["kinds"][kind] = {
                "per_s": round(len(values) / load.seconds, 1),
                "p50_ms": round(driver.percentile(values, 0.5) * 1000, 1),
                "p95_ms": round(driver.percentile(values, 0.95) * 1000, 1),
                "p99_ms": round(driver.percentile(values, 0.99) * 1000, 1),
            }
        row["other_cpu_cores"] = [round(cpu_cores(a, b), 2) for a, b in zip(others_before, others_after)]
        row["failed_because"] = failure(row, total, load)
        return row


def delivered(server: Server) -> int:
    return server.probe.scalar("SELECT count(*) FROM outbound WHERE status = 'delivered'")


def failure(row: dict, total: int, load: Load) -> list:
    reasons = []
    errors = sum(row["errors"].values())
    if errors > ERROR_LIMIT * max(total + errors, 1):
        reasons.append(f"errors {errors} of {total + errors}")
    for kind, stats in row["kinds"].items():
        if stats["p95_ms"] > P95_LIMIT_S * 1000:
            reasons.append(f"{kind} p95 {stats['p95_ms']} ms")
    send_rate = load.rates.get("send", 0)
    if send_rate and row["pending_at_end"] > max(send_rate * BACKLOG_LIMIT_SECONDS, 50):
        reasons.append(f"{row['pending_at_end']} messages waiting")
    if not row["alive"]:
        reasons.append("server died")
    return reasons


def wait_for_drain(server: Server, limit: float) -> float | None:
    started = time.time()
    while time.time() - started < limit:
        if server.probe.scalar("SELECT count(*) FROM outbound WHERE status = 'pending'") == 0:
            return round(time.time() - started, 1)
        time.sleep(1)
    return None


def calibrate(run: Run, args) -> None:
    """How fast the driver and Docker's port forwarding go on a request that does nothing."""
    server = run.server()
    try:
        for rate in (500, 1000, 2000, 4000, 8000):
            load = Load(server.url, server.domain, run.seed, 1, 10, {"host_info": rate})
            row = run.record("calibrate", run.step(server, load))
            if row["failed_because"]:
                break
    finally:
        server.stop()


def measure_drain(run: Run, sender: Server, receiver: Server, label: str, args) -> None:
    """Queues far more than can go out, then watches how fast it leaves."""
    owners = 60
    run.registered.pop(sender.name, None)
    run.registered.pop(receiver.name, None)
    run.register(sender, owners)
    if receiver is not sender:
        run.register(receiver, owners)
    load = Load(sender.url, sender.domain, run.seed, owners, args.stuff_seconds, {"send": args.stuff_rate},
                recipient_host=receiver.domain)
    others = (receiver,) if receiver is not sender else ()
    stuffed = run.record("delivery_stuff", {"label": label, **run.step(sender, load, others)})
    window_started = time.time()
    before = sender.probe.cgroup()
    others_before = [other.probe.cgroup() for other in others]
    first_delivered = delivered(sender)
    last_delivered, last_at = first_delivered, time.time()
    pending = sender.probe.scalar("SELECT count(*) FROM outbound WHERE status = 'pending'")
    while time.time() - window_started < args.window and pending > 0:
        time.sleep(2)
        pending = sender.probe.scalar("SELECT count(*) FROM outbound WHERE status = 'pending'")
        last_delivered, last_at = delivered(sender), time.time()
    after = sender.probe.cgroup()
    others_after = [other.probe.cgroup() for other in others]
    times = sender.probe.sql(
        "SELECT extract(epoch FROM last_attempt_at) FROM outbound "
        f"WHERE status = 'delivered' AND last_attempt_at >= to_timestamp({window_started}) ORDER BY 1")
    stamps = [float(line) for line in times.splitlines()]
    # Bursts of finishes separated by a gap show the worker's passes.
    bursts = []
    for stamp in stamps:
        if bursts and stamp - bursts[-1][-1] < 0.05:
            bursts[-1].append(stamp)
        else:
            bursts.append([stamp])
    per_second = {}
    for stamp in stamps:
        per_second[int(stamp)] = per_second.get(int(stamp), 0) + 1
    full_seconds = list(per_second.values())[1:-1] or [0]
    run.record("delivery", {
        "label": label, "stuff_accept_per_s": stuffed["kinds"].get("send", {}).get("per_s"),
        "stuff_send_p95_ms": stuffed["kinds"].get("send", {}).get("p95_ms"),
        "pending_at_start": stuffed["pending_at_end"], "pending_at_end": pending,
        "delivered_per_s": round((last_delivered - first_delivered) / (last_at - window_started), 1),
        "median_per_s": median(full_seconds), "peak_per_s": max(full_seconds),
        "bursts": len(bursts), "median_burst": median(len(b) for b in bursts) if bursts else 0,
        "seconds_per_burst": round((stamps[-1] - stamps[0]) / max(len(bursts) - 1, 1), 3) if stamps else 0,
        "cpu_cores": round(cpu_cores(before, after), 2), "throttled": round(throttled_share(before, after), 2),
        "receiver_cpu_cores": [round(cpu_cores(a, b), 2) for a, b in zip(others_before, others_after)],
        "memory_mb": round(after.get("memory_current", 0) / 1e6), "host_rss_mb": round(after.get("host_rss_kb", 0) / 1e3),
        "retries": sender.probe.scalar("SELECT count(*) FROM outbound WHERE attempts > 1"),
        "failures": sender.probe.sql("SELECT last_failure, count(*) FROM outbound WHERE last_failure IS NOT NULL GROUP BY 1"),
    })


def delivery(run: Run, args) -> None:
    server = run.server()
    try:
        measure_drain(run, server, server, "self", args)
    finally:
        server.stop()
    a_name, b_name = f"splint-test-load-{run.profile}", f"splint-test-load-{run.profile}-b"
    b = run.server("-b", peers=f"{a_name}:8080")
    a = run.server("", peers=f"{b_name}:8080")
    try:
        measure_drain(run, a, b, "two hosts", args)
    finally:
        a.stop()
        b.stop()


def scratch_image(args) -> None:
    """Builds a scratch copy with different delivery constants, without touching the real source."""
    with tempfile.TemporaryDirectory(dir=args.scratch_dir) as directory:
        copy = Path(directory) / "packages"
        shutil.copytree(PACKAGES, copy, ignore=shutil.ignore_patterns("target"))
        source = copy / "host/src/delivery.rs"
        text = source.read_text()
        for old, new in (
            ("Duration::from_millis(250)", f"Duration::from_millis({args.interval_ms})"),
            ("const MAX_IN_FLIGHT: usize = 32;", f"const MAX_IN_FLIGHT: usize = {args.in_flight};"),
            ("const MAX_IN_FLIGHT_PER_PEER: usize = 8;", f"const MAX_IN_FLIGHT_PER_PEER: usize = {args.per_peer};"),
        ):
            if old not in text:
                raise SystemExit(f"delivery.rs no longer contains {old}")
            text = text.replace(old, new)
        source.write_text(text)
        toolchain = next(line for line in (PACKAGES / "rust-toolchain.toml").read_text().splitlines()
                         if line.startswith("channel")).split('"')[1]
        subprocess.run(
            ["docker", "build", "--no-cache", "--tag", args.tag, "--build-arg", f"RUST_VERSION={toolchain}",
             "--file", str(TEST_SERVER / "Dockerfile"), "--build-context", f"scripts={TEST_SERVER}", str(copy)],
            check=True)


def ramp(run: Run, server: Server, label: str, load: Load, rates: list, seconds: float) -> None:
    for rate in rates:
        # The machine is shared, so a stall from something else isn't taken as this rate failing.
        for attempt in (1, 2):
            step = run.step(server, replace(load, seconds=seconds, rates={"pull": rate}))
            row = run.record("inbox", {"label": label, "attempt": attempt, **step})
            time.sleep(3)
            if not row["failed_because"]:
                break
        if row["failed_because"]:
            break


def plant_held(server: Server, template: str, each: int, first: int, last: int, seed: str) -> None:
    """Puts unread messages straight into the table. The pull doesn't verify them, and each row has a real envelope's size."""
    server.probe.sql(
        "INSERT INTO inbox (recipient, message_id, envelope, sender_identity, expires_at) "
        f"SELECT a.id, md5(a.id || g) || md5(g::text), '{template}', a.identity, extract(epoch FROM now())::bigint + 86400 "
        f"FROM agents a, generate_series(1, {each}) g "
        f"WHERE a.handle ~ '^load-{seed}-' AND split_part(a.handle, '-', 3)::int >= {first} "
        f"AND split_part(a.handle, '-', 3)::int < {last}")
    server.probe.sql("VACUUM ANALYZE inbox")


def real_envelope(run: Run) -> str:
    agent = Agent(run.seed, 0)
    return agent.seal(agent.id, b64(driver.os.urandom(750)), driver.LIFETIME_SECS)


def inbox(run: Run, args) -> None:
    """Signed pulls a second under the limit, for inboxes that are empty and ones that hold messages."""
    rates = args.rates
    owners = args.inbox_owners
    server = run.server()
    try:
        run.register(server, owners)
        load = Load(server.url, server.domain, run.seed, owners, args.step_seconds, ack=False)
        ramp(run, server, "empty", load, rates, args.step_seconds)
        plant_held(server, real_envelope(run), 5, 0, owners, run.seed)
        ramp(run, server, "5 unread", load, rates, args.step_seconds)
        server.probe.sql("TRUNCATE inbox")
        plant_held(server, real_envelope(run), 100, 0, owners, run.seed)
        ramp(run, server, "full page, 100 unread", load, [r for r in rates if r <= 1600], args.step_seconds)
    finally:
        server.stop()


def mixed(run: Run, args) -> None:
    """Steps up owners at the assumed rates, on a fresh server for each model, until something fails."""
    for name, per_day, factor, steps in (
        ("20/day peak", 20, PEAK_FACTOR, [100, 1000, 5000, 10000, 15000, 20000, 50000, 100000, 150000]),
        ("20/day average", 20, 1, [20000, 50000, 100000, 150000, 200000, 300000]),
        ("200/day peak", 200, PEAK_FACTOR, [100, 500, 1000, 1500, 2000, 5000, 10000, 15000]),
        ("200/day average", 200, 1, [1000, 5000, 10000, 15000, 20000, 50000]),
    ):
        if args.only and args.only not in name:
            continue
        server = run.server()
        run.registered.pop(server.name, None)
        try:
            for owners in steps:
                run.register(server, owners)
                rates = {"pull": owners / 60, "send": owners * per_day * factor / SECONDS_PER_DAY}
                load = Load(server.url, server.domain, run.seed, owners, args.step_seconds, rates)
                # The machine is shared, so a stall from something else isn't taken as a failure.
                for attempt in (1, 2):
                    row = run.step(server, load)
                    row.update(model=name, attempt=attempt, drain_seconds=wait_for_drain(server, 60))
                    run.record("mixed", row)
                    if not row["failed_because"]:
                        break
                if row["failed_because"]:
                    break
        finally:
            server.stop()


def retention(run: Run, args) -> None:
    """Real bytes per message from real traffic, then a full retention period's rows, a restore from them, and pulls."""
    server = run.server()
    free_gb = int(server.probe.exec("df", "-k", "--output=avail", "/").stdout.split()[-1]) / 2**20
    if free_gb < MIN_FREE_DOCKER_GB + 2:
        server.stop()
        raise SystemExit(f"only {free_gb:.1f}GB free on the Docker disk, which other projects share")
    try:
        owners = 100
        run.register(server, owners)
        start = server.probe.sizes()
        count = args.flow_messages
        load = Load(server.url, server.domain, run.seed, owners, count / 25, {"send": 25})
        sent = run.step(server, load)
        wait_for_drain(server, 180)
        stored = server.probe.sizes()
        server.probe.sql("SELECT pg_switch_wal()")
        run.record("storage_flow", {"stage": "sent and delivered, unread", "send": sent["kinds"].get("send"), "start": start, "sizes": stored,
                                    "messages": server.probe.scalar("SELECT count(*) FROM inbox")})
        pull = Load(server.url, server.domain, run.seed, owners, 60, {"pull": 50})
        run.step(server, pull)
        acked = server.probe.sizes()
        unacked = server.probe.scalar("SELECT count(*) FROM inbox WHERE NOT acked")
        run.record("storage_flow", {"stage": "pulled and acked", "unacked": unacked, "sizes": acked})
        server.probe.sql("VACUUM")
        vacuumed = server.probe.sizes()
        run.record("storage_flow", {"stage": "after vacuum", "sizes": vacuumed})

        fill_owners, per_owner = args.fill_owners, args.fill_per_owner
        run.register(server, fill_owners)
        started = time.time()
        fill(server, run.seed, fill_owners, per_owner)
        filled = server.probe.sizes()
        run.record("storage_fill", {"owners": fill_owners, "rows_per_owner": per_owner, "fill_seconds": round(time.time() - started),
                                    "sizes": filled, "explain": explain_pull(server, Agent(run.seed, 1).id)})
        before = server.probe.cgroup()
        scans = server.probe.sql("SELECT seq_scan, seq_tup_read FROM pg_stat_user_tables WHERE relname = 'inbox'")
        time.sleep(args.idle_seconds)
        after = server.probe.cgroup()
        run.record("storage_idle", {
            "seconds": args.idle_seconds, "cpu_cores": round(cpu_cores(before, after), 3), "memory_mb": round(after["memory_current"] / 1e6),
            "anon_mb": round(after.get("anon", 0) / 1e6), "inbox_scans_before": scans,
            "inbox_scans_after": server.probe.sql("SELECT seq_scan, seq_tup_read FROM pg_stat_user_tables WHERE relname = 'inbox'"),
        })
        load = Load(server.url, server.domain, run.seed, fill_owners, args.step_seconds, ack=False)
        ramp(run, server, f"{per_owner} acked rows each, {fill_owners} owners", load, args.rates, args.step_seconds)
        mix_owners = fill_owners
        rates = {"pull": mix_owners / 60, "send": mix_owners * 20 * PEAK_FACTOR / SECONDS_PER_DAY}
        row = run.step(server, Load(server.url, server.domain, run.seed, mix_owners, 60, rates))
        row["model"] = "20/day peak on the filled database"
        row["drain_seconds"] = wait_for_drain(server, 60)
        run.record("mixed", row)
        restore(run, server, fill_owners, args)
    finally:
        server.stop()


def pull_index(run: Run, args) -> None:
    """Pulls and the mixed model on a full database, without and then with an index on unread rows alone.

    The index exists only in this scratch database, to show what it would do. The product isn't changed.
    """
    server = run.server()
    owners = args.fill_owners
    try:
        run.register(server, owners)
        fill(server, run.seed, owners, args.fill_per_owner)
        load = Load(server.url, server.domain, run.seed, owners, args.step_seconds, ack=False)
        rates = {"pull": owners / 60, "send": owners * 20 * PEAK_FACTOR / SECONDS_PER_DAY}
        mix = Load(server.url, server.domain, run.seed, owners, 45, rates)
        for label, pull_rates in (("no extra index", [200, 400, 800]), ("index on unread", args.rates)):
            if label == "index on unread":
                server.probe.sql("CREATE INDEX load_test_unread ON inbox (recipient, seq) WHERE NOT acked")
                server.probe.sql("ANALYZE inbox")
                run.record("pull_index", {"explain": explain_pull(server, Agent(run.seed, 1).id)})
            row = run.step(server, mix)
            row.update(model=f"20/day peak on the filled database, {label}", drain_seconds=wait_for_drain(server, 60))
            run.record("mixed", row)
            ramp(run, server, f"{args.fill_per_owner} acked rows each, {owners} owners, {label}", load, pull_rates, args.step_seconds)
    finally:
        server.stop()


def fill(server: Server, seed: str, owners: int, per_owner: int) -> None:
    """A retention period's delivered and acknowledged rows, in random order as real traffic scatters them."""
    server.probe.sql(
        "INSERT INTO inbox (recipient, message_id, envelope, sender_identity, expires_at, acked) "
        "SELECT a.id, md5(a.id || g) || md5(g::text), '', '', "
        "extract(epoch FROM now())::bigint + 3600 + (random() * 600000)::bigint, TRUE "
        f"FROM agents a, generate_series(1, {per_owner}) g WHERE a.handle ~ '^load-{seed}-' ORDER BY random()")
    server.probe.sql(
        "INSERT INTO outbound (message_id, sender, envelope, sender_identity, recipient_host, expires_at, status, attempts, last_attempt_at) "
        f"SELECT md5(a.id || g) || md5(g::text), a.id, '', '', '{server.domain}', "
        "extract(epoch FROM now())::bigint + 3600 + (random() * 600000)::bigint, 'delivered', 1, now() - random() * interval '7 days' "
        f"FROM agents a, generate_series(1, {per_owner}) g WHERE a.handle ~ '^load-{seed}-' ORDER BY random()")
    server.probe.sql("VACUUM ANALYZE")
    # So the first step afterwards measures pulls and not this fill's writes reaching the disk.
    server.probe.sql("CHECKPOINT")


def explain_pull(server: Server, agent_id: str) -> str:
    return server.probe.sql(
        "EXPLAIN (ANALYZE, BUFFERS) SELECT seq, envelope, sender_identity FROM inbox "
        f"WHERE recipient = '{agent_id}' AND NOT acked AND expires_at > 0 ORDER BY seq LIMIT 100")


def restore(run: Run, server: Server, owners: int, args) -> None:
    """Dumps the loaded database, starts an empty server of the same name, restores into it and uses it."""
    counts = {t: server.probe.scalar(f"SELECT count(*) FROM {t}") for t in ("agents", "outbound", "inbox")}
    size = server.probe.scalar("SELECT pg_database_size(current_database())")
    dump_path = args.scratch_dir / f"splint-load-{run.profile}.dump"
    try:
        started = time.time()
        with dump_path.open("wb") as file:
            subprocess.run(["docker", "exec", server.name, "pg_dump", "-U", "postgres", "-Fc", "postgres"], stdout=file, check=True)
        dump_seconds = time.time() - started
        server.stop()
        server.start()
        started = time.time()
        with dump_path.open("rb") as file:
            done = subprocess.run(
                ["docker", "exec", "-i", server.name, "pg_restore", "-U", "postgres", "-d", "postgres", "--clean", "--if-exists", "--no-owner"],
                stdin=file, capture_output=True, text=True)
        restore_seconds = time.time() - started
        started = time.time()
        server.probe.sql("VACUUM ANALYZE")
        analyze_seconds = time.time() - started
        restored = {t: server.probe.scalar(f"SELECT count(*) FROM {t}") for t in ("agents", "outbound", "inbox")}
        rates = {"pull": 100, "send": 5}
        row = run.step(server, Load(server.url, server.domain, run.seed, owners, 15, rates))
        run.record("restore", {
            "database_mb": round(size / 1e6), "dump_mb": round(dump_path.stat().st_size / 1e6),
            "dump_seconds": round(dump_seconds, 1), "restore_seconds": round(restore_seconds, 1), "analyze_seconds": round(analyze_seconds, 1),
            "counts_before": counts, "counts_after": restored, "restore_returncode": done.returncode,
            "restore_stderr": done.stderr[-400:], "after_restore_step": row,
            "drained_seconds": wait_for_drain(server, 30),
        })
    finally:
        dump_path.unlink(missing_ok=True)


def probe_requests(server: Server, seed: str, tries: int = 5) -> dict:
    """Fresh connections, as a new client would make, with one host-info call and one signed pull."""
    answered, slowest, agent = 0, 0.0, Agent(seed, 1)
    for _ in range(tries):
        started = time.time()
        try:
            proof = agent.access_proof(server.domain, "GET", driver.INBOX)
            request = urllib.request.Request(server.url + driver.INBOX, headers={"Authorization": f"Splint {proof}"})
            with urllib.request.urlopen(request, timeout=5) as response:
                answered += response.status == 200
        except OSError:
            pass
        slowest = max(slowest, time.time() - started)
    return {"answered": f"{answered}/{tries}", "slowest_ms": round(slowest * 1000)}


def hold_connections(server: Server, how_many: int, held: list) -> None:
    """Holds sockets open: a third do nothing, a third stop mid-header and a third stop mid-body."""
    while len(held) < how_many:
        connection = socket.create_connection(("127.0.0.1", server.port), timeout=10)
        kind = len(held) % 3
        if kind == 1:
            connection.sendall(b"GET /v0/inbox HTTP/1.1\r\nHost: x\r\nX-Slow: ")
        elif kind == 2:
            connection.sendall(b"POST /v0/outbound HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{")
        held.append(connection)


def connections(run: Run, args) -> None:
    """Issue 93: how many idle or slow connections stop the host, and whether delivery stops with it."""
    for nofile, levels in ((1024, [100, 500, 900, 1000, 1010, 1020, 1030, 1100]),
                           (None, [1000, 3000, 6000, 9000, 12000, 15000])):
        server = run.server(nofile=nofile)
        run.registered.pop(server.name, None)
        held = []
        try:
            run.register(server, 50)
            # A backlog keeps the delivery worker busy throughout, so a stall shows in its count.
            run.step(server, Load(server.url, server.domain, run.seed, 50, 10, {"send": 200}))
            stopped_at = None
            for level in levels:
                try:
                    hold_connections(server, level, held)
                    opening = "ok"
                except OSError as error:
                    opening = type(error).__name__
                before = delivered(server)
                time.sleep(5)
                delivered_rate = (delivered(server) - before) / 5
                state = server.probe.cgroup()
                answers = probe_requests(server, run.seed)
                row = run.record("connections", {
                    "file_limit": nofile or "default", "held": len(held), "opening": opening, "probe": answers,
                    "delivered_per_s_while_held": delivered_rate, "pending": server.probe.scalar("SELECT count(*) FROM outbound WHERE status='pending'"),
                    "host_fds": state.get("host_fds"), "host_rss_mb": round(state.get("host_rss_kb", 0) / 1e3),
                    "memory_mb": round(state.get("memory_current", 0) / 1e6),
                    "accept_errors": server.probe.docker_log_tail(50).count("accept error"),
                })
                if not row["probe"]["answered"].startswith("5") or opening != "ok":
                    stopped_at = len(held)
                    break
            for connection in held:
                connection.close()
            released = time.time()
            time.sleep(1)
            run.record("connections_released", {
                "file_limit": nofile or "default", "stopped_at": stopped_at, "probe_after_release": probe_requests(server, run.seed),
                "seconds_after_release": round(time.time() - released, 1),
            })
        finally:
            for connection in held:
                connection.close()
            server.stop()


SCENARIOS = {f.__name__: f for f in (calibrate, delivery, inbox, mixed, retention, pull_index, connections)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=[*SCENARIOS, "all", "scratch-image"])
    parser.add_argument("--profile", choices=PORTS, default="small")
    parser.add_argument("--out", type=Path, default=Path(tempfile.gettempdir()) / "splint-load.jsonl")
    parser.add_argument("--scratch-dir", type=Path, default=Path(tempfile.gettempdir()))
    parser.add_argument("--image", default="splint-test-server")
    parser.add_argument("--window", type=float, default=30, help="seconds to watch a delivery backlog drain")
    parser.add_argument("--stuff-rate", type=int, default=300)
    parser.add_argument("--stuff-seconds", type=int, default=15)
    parser.add_argument("--step-seconds", type=float, default=30)
    parser.add_argument("--rates", type=lambda s: [int(x) for x in s.split(",")],
                        default=[100, 200, 400, 800, 1200, 1600, 2400, 3200, 4800])
    parser.add_argument("--inbox-owners", type=int, default=1000)
    parser.add_argument("--only", help="run only the mixed models whose name contains this")
    parser.add_argument("--flow-messages", type=int, default=1500)
    parser.add_argument("--fill-owners", type=int, default=5000)
    parser.add_argument("--fill-per-owner", type=int, default=140, help="20 a day for the default 7 days")
    parser.add_argument("--idle-seconds", type=float, default=70)
    parser.add_argument("--tag", default="splint-test-server-scratch")
    parser.add_argument("--interval-ms", type=int, default=250)
    parser.add_argument("--in-flight", type=int, default=32)
    parser.add_argument("--per-peer", type=int, default=8)
    args = parser.parse_args()
    if args.scenario == "scratch-image":
        scratch_image(args)
        return
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    driver.raise_fd_limit()
    context = multiprocessing.get_context("spawn")
    with context.Pool(WORKERS, initializer=driver.raise_fd_limit) as pool:
        run = Run(pool, args.out, args.profile, args.image)
        for scenario in SCENARIOS if args.scenario == "all" else [args.scenario]:
            SCENARIOS[scenario](run, args)


if __name__ == "__main__":
    main()
