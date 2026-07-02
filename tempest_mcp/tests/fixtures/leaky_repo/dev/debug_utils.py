"""PLANTED LEAK — Rule (c): prod data reaching a non-prod logging/debug sink.

dump_debug_log lives under dev/ (NON-PROD) and is labeled as a debug sink
(matches `sink_patterns`: 'debug'/'dump'/'log'). It pulls a real record from
prod.user_service.ProdUserService (a prod_data source) and prints it —
sensitive production data ending up in a local debug log.
"""

from prod.user_service import ProdUserService


def dump_debug_log(user_id):
    service = ProdUserService()
    record = service.get_user_record(user_id)
    print(f"[DEBUG] fetched prod record: {record}")
    return record
