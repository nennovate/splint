"""Reads a test server from outside: its cgroup counters and its database."""

import subprocess
import time


class ServerProbe:
    def __init__(self, name: str):
        self.name = name

    def exec(self, *command: str, **kwargs) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["docker", "exec", "-i", self.name, *command], capture_output=True, text=True, **kwargs)

    def sql(self, statement: str) -> str:
        done = self.exec("psql", "-U", "postgres", "-At", "-c", statement)
        if done.returncode != 0:
            raise RuntimeError(f"sql failed: {done.stderr.strip()} ({statement:.80})")
        return done.stdout.strip()

    def scalar(self, statement: str) -> int:
        return int(float(self.sql(statement) or 0))

    def cgroup(self) -> dict:
        script = (
            "cat /sys/fs/cgroup/cpu.stat /sys/fs/cgroup/memory.stat /sys/fs/cgroup/memory.events;"
            "echo memory_current $(cat /sys/fs/cgroup/memory.current);"
            "host=$(pidof host);"
            "echo host_fds $(ls /proc/$host/fd | wc -l);"
            "echo host_rss_kb $(awk '/VmRSS/{print $2}' /proc/$host/status);"
            "echo host_threads $(awk '/Threads/{print $2}' /proc/$host/status)"
        )
        out = self.exec("sh", "-c", script).stdout
        values = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1].isdigit():
                values[parts[0]] = int(parts[1])
        values["at"] = time.time()
        return values

    def alive(self) -> bool:
        done = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Running}} {{.State.OOMKilled}}", self.name],
            capture_output=True, text=True)
        return done.stdout.startswith("true")

    def docker_log_tail(self, lines: int = 200) -> str:
        done = subprocess.run(["docker", "logs", "--tail", str(lines), self.name], capture_output=True, text=True)
        return done.stdout + done.stderr

    def sizes(self) -> dict:
        """Heap with TOAST, indexes and row counts for each table, plus the WAL position."""
        rows = self.sql(
            "SELECT relname, pg_table_size(oid), pg_indexes_size(oid), "
            "(SELECT n_live_tup FROM pg_stat_user_tables s WHERE s.relid = c.oid), "
            "(SELECT n_dead_tup FROM pg_stat_user_tables s WHERE s.relid = c.oid) "
            "FROM pg_class c WHERE relname IN ('agents','outbound','inbox')")
        sizes = {}
        for row in rows.splitlines():
            name, table, indexes, live, dead = row.split("|")
            sizes[name] = {"table": int(table), "indexes": int(indexes), "live": int(live), "dead": int(dead)}
        sizes["database"] = self.scalar("SELECT pg_database_size(current_database())")
        sizes["wal_lsn_bytes"] = self.scalar("SELECT pg_wal_lsn_diff(pg_current_wal_lsn(), '0/0')")
        sizes["wal_dir"] = self.scalar("SELECT sum(size) FROM pg_ls_waldir()")
        return sizes


def cpu_cores(before: dict, after: dict) -> float:
    elapsed = max(after["at"] - before["at"], 0.001)
    return (after.get("usage_usec", 0) - before.get("usage_usec", 0)) / 1e6 / elapsed


def throttled_share(before: dict, after: dict) -> float:
    elapsed = max(after["at"] - before["at"], 0.001)
    return (after.get("throttled_usec", 0) - before.get("throttled_usec", 0)) / 1e6 / elapsed
