"""Local/dev-only user service. NON-PROD data source — not a leak target for
Rule (c) even though it's read by a debug sink below."""

from dev.local_db import LocalDatabase


class LocalUserService:
    """Returns fake/local user records for development."""

    def __init__(self):
        self.db = LocalDatabase()

    def get_user_record(self, user_id):
        self.db.connect()
        return {"user_id": user_id, "email": f"localuser{user_id}@example.test"}
