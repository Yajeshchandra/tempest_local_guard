"""Production database access layer. This is a Production Boundary Node:
PROD-tagged (folder marker `prod/`) AND structurally a resource boundary
(class name matches the `database` PBN pattern)."""


class ProdDatabase:
    """Connects to the live production Postgres cluster."""

    def __init__(self, host="prod-db.internal.example.com"):
        self.host = host
        self.connection = None

    def connect(self):
        self.connection = f"connected:{self.host}"
        return self.connection

    def write(self, table, record):
        """Persist a record to the production database."""
        return {"table": table, "record": record, "host": self.host}
