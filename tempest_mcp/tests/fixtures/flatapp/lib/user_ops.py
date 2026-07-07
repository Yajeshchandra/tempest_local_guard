"""A one-off data backfill living in lib/ (NOT a test/dev/scripts folder, and
not a test_* filename). It IS non-prod code — it imports faker to generate
data — and it reaches the real prod Database. Folder-only detection would miss
this; the framework-import signal catches it."""
import faker

from app.db import Database


def backfill():
    fake = faker.Faker()
    db = Database()
    db.write("users", {"email": fake.email()})
