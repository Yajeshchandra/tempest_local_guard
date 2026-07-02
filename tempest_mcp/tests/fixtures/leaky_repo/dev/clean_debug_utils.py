"""CLEAN SIBLING for Rule (c): dumps only local/dev data to a debug log.
Must NOT trigger a finding — this is the false-positive control for Rule (c)."""

from dev.local_user_service import LocalUserService


def dump_local_debug_log(user_id):
    service = LocalUserService()
    record = service.get_user_record(user_id)
    print(f"[DEBUG] fetched local record: {record}")
    return record
