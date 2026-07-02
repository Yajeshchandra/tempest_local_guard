"""PLANTED LEAK — Rule (b): test/seed code writing to a prod resource.

This lives under tests/ (TEST-tagged by folder marker) but instantiates and
writes to prod.db.ProdDatabase (a PBN of boundary_type=database). A seed
script like this should target a local/test database, not production.
"""

from prod.db import ProdDatabase


def seed_fake_users():
    db = ProdDatabase()
    db.connect()
    db.write("users", {"name": "fixture-user", "email": "fixture@example.com"})
    return db
