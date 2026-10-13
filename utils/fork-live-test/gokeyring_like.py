# Like go-keyring (used by glab): a NEW D-Bus connection for every keyring call.
import os, subprocess, sys
import secretstorage

def conn_call(fn):
    conn = secretstorage.dbus_init()
    try:
        return fn(secretstorage.get_default_collection(conn))
    finally:
        conn.close()

def read(coll, attrs):
    item = next(coll.search_items(attrs))
    if item.is_locked() and item.unlock():
        return None  # prompt dismissed
    try:
        return item.get_secret()
    except secretstorage.exceptions.LockedException:
        return None

mode = sys.argv[1]
if mode == "lookups":  # several lookups of one entry, one connection each
    for i in range(int(sys.argv[2])):
        got = conn_call(lambda c: read(c, {"service": "glab"}))
        print(f"  connection {i + 1}: {'got secret' if got == b'dummy-1' else 'NO SECRET'}")
elif mode == "spawn":  # run secret-tool as a child of this process
    got = subprocess.run(["secret-tool", "lookup", "service", "glab"], capture_output=True).stdout
    print(f"  secret-tool under python: {'got secret' if got == b'dummy-1' else 'NO SECRET'}")
elif mode == "probe":  # glab's keyring probe: create, read back, delete, each on its own connection
    attrs = {"service": "probe", "pid": str(os.getpid())}
    conn_call(lambda c: c.create_item(f"glab:__keyring_probe__:{os.getpid()}:1", attrs, b"probe"))
    got = conn_call(lambda c: read(c, attrs))
    try:
        conn_call(lambda c: next(c.search_items(attrs)).delete())
        deleted = "deleted"
    except secretstorage.exceptions.LockedException:
        deleted = "NOT DELETED (locked)"
    print(f"  probe item: {'read back' if got == b'probe' else 'NOT READ'}, {deleted}")
