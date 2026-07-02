"""Production user service. PROD-tagged (folder marker `prod/`) and matches
the `sensitive_data_keywords` list (label contains 'user'), so it's treated
as a prod_data source for Rule (c)."""

from prod.db import ProdDatabase


class ProdUserService:
    """Fetches real user records from the production database."""

    def __init__(self):
        self.db = ProdDatabase()

    def get_user_record(self, user_id):
        self.db.connect()
        return {"user_id": user_id, "email": f"user{user_id}@example.com"}
