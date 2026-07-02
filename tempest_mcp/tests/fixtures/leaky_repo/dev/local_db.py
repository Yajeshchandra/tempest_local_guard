"""Local development database stub. NON-PROD, not a PBN target for prod."""


class LocalDatabase:
    """An in-memory/local dev database — not connected to anything real."""

    def __init__(self, host="localhost"):
        self.host = host
        self.records = []

    def connect(self):
        return f"connected:{self.host}"

    def write(self, table, record):
        self.records.append((table, record))
        return {"table": table, "record": record, "host": self.host}
