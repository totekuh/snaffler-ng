"""Shared fixtures for deb integration tests.

All tests run against the *installed* snaffler-ng package, not source tree.
"""

import os
import signal
import sqlite3
import subprocess
import tempfile
import time

import pytest
import requests


@pytest.fixture
def scan_db():
    """Create a temporary scan DB with schema and sample findings."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    conn = sqlite3.connect(path)
    conn.executescript("""
        CREATE TABLE sync (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE target_computer
            (name TEXT PRIMARY KEY COLLATE NOCASE, ip TEXT, done INTEGER DEFAULT 0);
        CREATE TABLE target_share
            (unc_path TEXT PRIMARY KEY COLLATE NOCASE, done INTEGER DEFAULT 0,
             readable INTEGER DEFAULT 1);
        CREATE TABLE target_dir
            (path TEXT PRIMARY KEY, walked INTEGER DEFAULT 0);
        CREATE TABLE target_file
            (path TEXT PRIMARY KEY, checked INTEGER DEFAULT 0);
        CREATE TABLE finding
            (finding_id TEXT, file_path TEXT, triage TEXT, rule_name TEXT,
             match_text TEXT, context TEXT, size INTEGER, mtime TEXT, found_at TEXT);
    """)
    conn.execute("INSERT INTO sync VALUES ('domain', 'TESTLAB.LOCAL')")
    for i in range(5):
        conn.execute(
            "INSERT INTO target_computer (name, ip, done) VALUES (?, ?, 1)",
            (f"PC{i}.testlab.local", f"10.0.0.{i+1}"),
        )
    for i in range(3):
        conn.execute(
            "INSERT INTO target_share (unc_path, done) VALUES (?, 1)",
            (f"\\\\PC0\\share{i}",),
        )
    for i in range(3):
        conn.execute(
            "INSERT INTO target_dir (path, walked) VALUES (?, 1)",
            (f"\\\\PC0\\share{i}",),
        )
    for i in range(20):
        conn.execute(
            "INSERT INTO target_file (path, checked) VALUES (?, 1)",
            (f"\\\\PC0\\share0\\file{i}.txt",),
        )
    findings = [
        ("f1", "\\\\PC0\\share0\\passwords.txt", "Red", "KeepPass",
         "password=hunter2", "password=hunter2\nuser=admin", 1024),
        ("f2", "\\\\PC0\\share0\\id_rsa", "Red", "SshPrivateKey",
         "-----BEGIN RSA", "-----BEGIN RSA PRIVATE KEY-----", 2048),
        ("f3", "\\\\PC0\\share1\\web.config", "Yellow", "ConfigFile",
         "connectionString=", "Server=db;uid=sa;pwd=P@ss", 4096),
        ("f4", "\\\\PC0\\share1\\notes.txt", "Green", "InterestingFile",
         None, "meeting notes Q4", 512),
        ("f5", "\\\\PC0\\share2\\shadow", "Black", "NixShadowFile",
         "root:$6$salt$hash", "root:$6$salt$hash:19000:0:99999:7:::", 256),
    ]
    for fid, path_, triage, rule, match, ctx, size in findings:
        conn.execute(
            "INSERT INTO finding VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
            (fid, path_, triage, rule, match, ctx, size, "2026-01-15"),
        )
    conn.commit()
    conn.close()
    yield path
    os.unlink(path)


@pytest.fixture
def web_server(scan_db):
    """Start snaffler results --web and yield (process, port). Kills on teardown."""
    port = 18923
    proc = subprocess.Popen(
        ["snaffler", "results", "--web", "--web-port", str(port), "-s", scan_db],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            r = requests.get(f"http://127.0.0.1:{port}/", timeout=1)
            if r.status_code == 200:
                break
        except requests.ConnectionError:
            time.sleep(0.2)
    else:
        proc.kill()
        out = proc.stdout.read().decode(errors="replace")
        pytest.fail(f"Web server did not start in 10s. Output:\n{out}")

    yield proc, port

    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
