"""PLANTED LEAK — Rule (a): hardcoded prod secret in non-prod (TEST-tagged)
code. The connection string below matches `prod_identifier_patterns`
('prod-...') and the API key literal has high entropy, so it should be
flagged as a hardcoded production credential leaking into test fixtures.
"""

PROD_DB_CONNECTION_STRING = "postgres://admin:pw@prod-db.internal.example.com:5432/main"
PROD_API_KEY = "sk_live_9f8A2z7QpL4mX0vB6tR1yN3cW5jH8dE2"


def get_test_fixture_config():
    return {
        "connection": PROD_DB_CONNECTION_STRING,
        "api_key": PROD_API_KEY,
    }
