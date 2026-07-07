"""Test fixtures — non-prod. LEAK: constructs the real Database in a fixture."""
from app.db import Database


def make_db_fixture():
    db = Database()
    return db.read("SELECT 1")
