"""CLEAN SIBLING for Rule (a): only references local/fake test credentials.
Must NOT trigger a finding — this is the false-positive control for Rule (a)."""

TEST_DB_CONNECTION_STRING = "postgres://test:test@localhost:5432/test_db"
TEST_API_KEY = "fake-test-key-not-a-secret"


def get_clean_test_fixture_config():
    return {
        "connection": TEST_DB_CONNECTION_STRING,
        "api_key": TEST_API_KEY,
    }
