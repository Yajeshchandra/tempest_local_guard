"""CLEAN SIBLING for Rule (b): seeds the local dev database only. Must NOT
trigger a finding — this is the false-positive control for Rule (b)."""

from dev.local_db import LocalDatabase


def seed_fake_users_locally():
    db = LocalDatabase()
    db.connect()
    db.write("users", {"name": "fixture-user", "email": "fixture@example.com"})
    return db
