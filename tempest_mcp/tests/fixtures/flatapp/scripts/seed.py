"""Seed script — non-prod. LEAK: reaches the real Database directly."""
from app.db import Database


def seed_fake_users():
    db = Database()
    db.write("users", {"email": "fake@example.com"})
