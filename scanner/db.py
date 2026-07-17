
import os
import mysql.connector

MYSQL_CONFIG = {
    "host": os.environ.get("MYSQL_HOST", "localhost"),
    "user": os.environ.get("MYSQL_USER", "root"),
    "password": os.environ.get("MYSQL_PASSWORD", ""),
    "database": os.environ.get("MYSQL_DATABASE", "cloud_security_posture_db"),
}


class _Cursor:
    """Wraps a MySQL dict cursor and rewrites `?` placeholders to `%s`."""

    def __init__(self, cursor):
        self._cursor = cursor

    def execute(self, sql, params=()):
        return self._cursor.execute(sql.replace("?", "%s"), params)

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    @property
    def lastrowid(self):
        return self._cursor.lastrowid

    def close(self):
        return self._cursor.close()

    def __getattr__(self, name):
        return getattr(self._cursor, name)


class _Connection:
    def __init__(self, conn):
        self._conn = conn

    def cursor(self):
        # dictionary=True  -> rows are dicts, so row["col"] and dict(row) both work
        # buffered=True    -> safe to run a new query before draining the last result
        return _Cursor(self._conn.cursor(dictionary=True, buffered=True))

    def commit(self):
        return self._conn.commit()

    def close(self):
        return self._conn.close()

    def __getattr__(self, name):
        return getattr(self._conn, name)


def connect():
    """Return a connection that behaves like the old sqlite3 connection."""
    return _Connection(mysql.connector.connect(**MYSQL_CONFIG))
