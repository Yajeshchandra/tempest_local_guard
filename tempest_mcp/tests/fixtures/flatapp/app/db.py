"""The application's real database client. Note: NOT in a prod/ folder —
this is the realistic real-repo shape SP1 must handle."""
from sqlalchemy import create_engine

DATABASE_URL = "postgresql://appuser:s3cr3t@db.internal.example.com:5432/appdb"


class Database:
    def __init__(self):
        self.engine = create_engine(DATABASE_URL)

    def write(self, table, row):
        with self.engine.begin() as conn:
            conn.execute(table.insert().values(**row))

    def read(self, query):
        with self.engine.connect() as conn:
            return conn.execute(query).fetchall()
