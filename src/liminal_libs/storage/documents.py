"""Documents: what the publishers read (an agency's releases and rules, a vendor's headlines) and, as
they come, filings and records, kept in SQLite or MongoDB by the plugin's documents store (stores.py).

The user, 2026-10-31: "we can use a mongo db ... for mixed media", "i think im gonna need mongo for
downloading business records/tax filings etc", "each module needs to support sqlite or mongo or duck
db based on data type". A kind of document (Kind) has the same fields in either: in SQLite a table's
columns (a list as JSON), in MongoDB a collection's documents, each with its key as `_id`. Both
answer the same calls (put, find, newest, count, every), so a plugin's code does not change with
its store, and a move from one to the other (stores.settle) is a copy of `every` into `put`.

1.91.0 (Monday list item 10): an instance the user added on the platform's Databases section keeps them too, when a
plugin's pick names it (stores.py): `SqlDocuments`, a table each kind on a PostgreSQL or MariaDB database, or in a
SQLite file, answering the same calls; a MongoDB instance is a MongoDocuments on its database.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Iterable, Iterator


@dataclass(frozen=True)
class Kind:
    """A kind of document: its table (SQLite) and collection (MongoDB), the fields making its key,
    the field it is ordered by (newest first), its fields in the table's column order, and those
    kept as JSON in SQLite (lists)."""
    name: str
    table: str
    collection: str
    key: tuple[str, ...]
    order: str
    fields: tuple[str, ...]
    lists: tuple[str, ...] = ()
    numbers: tuple[str, ...] = ()  # its whole numbers (a time in ms): a server's table keeps them as numbers (1.91.0)

    def id(self, doc: dict) -> str:
        return ":".join(str(doc[k]) for k in self.key)


# An agency's items (gov.py: gov/gov.db's items) and a vendor's headlines (the main file's news).
GOV_ITEMS = Kind("gov_items", "items", "gov_items", ("source", "id"), "published",
                 ("source", "id", "agency", "title", "url", "published", "kind", "tags", "fetched_at"), ("tags",))
NEWS = Kind("news", "news", "news", ("source", "id"), "published_ms",
            ("source", "id", "published_ms", "title", "publisher", "url", "tickers"), ("tickers",), ("published_ms",))
KINDS = {k.name: k for k in (GOV_ITEMS, NEWS)}


class SqliteDocuments:
    """A kind's documents in a SQLite table of its fields."""
    engine = "sqlite"

    def __init__(self, conn: sqlite3.Connection, kind: Kind):
        self.conn, self.kind = conn, kind

    def _row(self, doc: dict) -> tuple:
        return tuple(json.dumps(doc.get(f) or []) if f in self.kind.lists else doc.get(f) for f in self.kind.fields)

    def _doc(self, row: tuple) -> dict:
        d = dict(zip(self.kind.fields, row))
        for f in self.kind.lists:
            d[f] = json.loads(d[f] or "[]")
        return d

    def put(self, docs: Iterable[dict], replace: bool = False) -> int:
        """Store documents; one held already is kept (`replace`: replaced). Returns how many were new
        (replaced: how many were given)."""
        rows = [self._row(d) for d in docs]
        with self.conn:
            before = self.conn.total_changes
            self.conn.executemany(f"INSERT OR {'REPLACE' if replace else 'IGNORE'} INTO {self.kind.table} "
                                  f"({', '.join(self.kind.fields)}) VALUES ({', '.join('?' * len(self.kind.fields))})", rows)
            changed = self.conn.total_changes - before
        return len(rows) if replace else changed

    def _where(self, where: dict | None, since) -> tuple[str, list]:
        sql, args = [], []
        for f, v in (where or {}).items():
            if isinstance(v, (list, tuple, set)):
                sql.append(f"{f} IN ({', '.join('?' * len(v))})")
                args += list(v)
            else:
                sql.append(f"{f}=?")
                args.append(v)
        if since is not None:
            sql.append(f"{self.kind.order} >= ?")
            args.append(since)
        return (" WHERE " + " AND ".join(sql)) if sql else "", args

    def find(self, where: dict | None = None, since=None, limit: int | None = None) -> list[dict]:
        """Documents matching `where` (a field's value, or one of a list), from `since` on (by the
        kind's order field), newest first."""
        w, args = self._where(where, since)
        sql = f"SELECT {', '.join(self.kind.fields)} FROM {self.kind.table}{w} ORDER BY {self.kind.order} DESC"
        if limit is not None:
            sql += " LIMIT ?"
            args.append(int(limit))
        return [self._doc(r) for r in self.conn.execute(sql, args)]

    def newest(self, where: dict | None = None):
        w, args = self._where(where, None)
        return self.conn.execute(f"SELECT MAX({self.kind.order}) FROM {self.kind.table}{w}", args).fetchone()[0]

    def count(self, where: dict | None = None) -> int:
        w, args = self._where(where, None)
        return self.conn.execute(f"SELECT COUNT(*) FROM {self.kind.table}{w}", args).fetchone()[0]

    def every(self, where: dict | None = None, batch: int = 5000) -> Iterator[list[dict]]:
        """All documents (matching `where`) a batch at a time, by key."""
        w, args = self._where(where, None)
        cur = self.conn.execute(f"SELECT {', '.join(self.kind.fields)} FROM {self.kind.table}{w} "
                                f"ORDER BY {', '.join(self.kind.key)}", args)
        while rows := cur.fetchmany(batch):
            yield [self._doc(r) for r in rows]


class MongoDocuments:
    """A kind's documents in a MongoDB collection, each with its key as `_id`."""
    engine = "mongodb"

    def __init__(self, db, kind: Kind):
        self.kind = kind
        self.coll = db[kind.collection]
        self._indexed = False

    def _index(self) -> None:
        if not self._indexed:
            self.coll.create_index([(self.kind.order, -1)])
            self.coll.create_index([(self.kind.key[0], 1), (self.kind.order, -1)])
            self._indexed = True

    def put(self, docs: Iterable[dict], replace: bool = False) -> int:
        from pymongo import ReplaceOne, UpdateOne

        docs = [{f: d.get(f) if f not in self.kind.lists else list(d.get(f) or []) for f in self.kind.fields}
                for d in docs]
        if not docs:
            return 0
        self._index()
        ops = [ReplaceOne({"_id": self.kind.id(d)}, {"_id": self.kind.id(d), **d}, upsert=True) if replace else
               UpdateOne({"_id": self.kind.id(d)}, {"$setOnInsert": d}, upsert=True) for d in docs]
        got = self.coll.bulk_write(ops, ordered=False)
        return len(docs) if replace else got.upserted_count

    @staticmethod
    def _filter(where: dict | None, order: str, since) -> dict:
        f = {k: {"$in": list(v)} if isinstance(v, (list, tuple, set)) else v for k, v in (where or {}).items()}
        if since is not None:
            f[order] = {"$gte": since}
        return f

    def _plain(self, d: dict) -> dict:
        return {f: d.get(f) if f not in self.kind.lists else list(d.get(f) or []) for f in self.kind.fields}

    def find(self, where: dict | None = None, since=None, limit: int | None = None) -> list[dict]:
        cur = self.coll.find(self._filter(where, self.kind.order, since)).sort(self.kind.order, -1)
        if limit is not None:
            cur = cur.limit(int(limit))
        return [self._plain(d) for d in cur]

    def newest(self, where: dict | None = None):
        d = self.coll.find_one(self._filter(where, self.kind.order, None), sort=[(self.kind.order, -1)])
        return d.get(self.kind.order) if d else None

    def count(self, where: dict | None = None) -> int:
        return self.coll.count_documents(self._filter(where, self.kind.order, None))

    def every(self, where: dict | None = None, batch: int = 5000) -> Iterator[list[dict]]:
        out = []
        for d in self.coll.find(self._filter(where, self.kind.order, None)).sort("_id", 1).batch_size(batch):
            out.append(self._plain(d))
            if len(out) >= batch:
                yield out
                out = []
        if out:
            yield out


# -- a kind's documents in an instance the user added (1.91.0, Monday list item 10) -------------------------------------
@dataclass(frozen=True)
class Dialect:
    """How a SQL engine is spoken to for a kind's table: a parameter's mark, an identifier's quotes, the types of its
    columns (a field's text, a text field that is indexed, a whole number), what follows CREATE TABLE, and how an insert
    keeps a document held already (`keep`) or replaces it (`replace`, each column `{c}` from what was given)."""

    name: str
    mark: str
    quote: str
    text: str
    keyed: str
    number: str
    keep: str
    replace: str
    replace_column: str
    table_tail: str = ""


_KEEP, _REPLACE, _REPLACE_COLUMN = (" ON CONFLICT (doc_id) DO NOTHING", " ON CONFLICT (doc_id) DO UPDATE SET {sets}",
                                    "{c} = EXCLUDED.{c}")
DIALECTS = {
    # PostgreSQL (pg8000: format marks); a SQLite file the user added speaks the same upsert (SQLite 3.24 and later)
    "postgres": Dialect("postgres", "%s", '"', "TEXT", "TEXT", "BIGINT", _KEEP, _REPLACE, _REPLACE_COLUMN),
    "sqlite": Dialect("sqlite", "?", '"', "TEXT", "TEXT", "INTEGER", _KEEP, _REPLACE, _REPLACE_COLUMN),
    # MariaDB (PyMySQL: format marks): an index on text needs a length, so the indexed text columns are VARCHAR(255); a
    # duplicate key alone is let by (never INSERT IGNORE, which lets a value cut short by, too)
    "mariadb": Dialect("mariadb", "%s", "`", "MEDIUMTEXT", "VARCHAR(255)", "BIGINT",
                       " ON DUPLICATE KEY UPDATE doc_id = doc_id", " ON DUPLICATE KEY UPDATE {sets}", "{c} = VALUES({c})",
                       " DEFAULT CHARSET=utf8mb4"),
}
TABLE_PREFIX = "liminal_"  # a kind's table on a server (liminal_gov_items, liminal_news): never one of the server's own
PUT_BATCH = 500  # documents written in one statement
_READY: set = set()  # (place, table): made in this process already
_READY_MOST = 256


def forget_tables() -> None:
    """The tables made looked for again at the next call (a connection closed, so perhaps another server's now)."""
    _READY.clear()


class SqlDocuments:
    """A kind's documents in a table of an instance the user added (stores.py: a pick naming one): a PostgreSQL or
    MariaDB database, or a SQLite file. One table for each kind (TABLE_PREFIX and its collection's name), its fields as
    columns (a list as JSON text, a whole number as a number, the rest as text, as gov.db and the main file keep them),
    and `doc_id`, the sha256 of its key, as the primary key. It answers the calls the other two answer (put, find,
    newest, count, every), so a plugin's code does not change with its store.

    `session`: a context manager giving a DB-API connection, held while one call runs (stores.py's, through the
    instance's plugin's `open`); `place`: the instance's name for this process's note of the tables it made. `every`
    reads a batch at a time by key, never the whole table."""

    def __init__(self, session, kind: Kind, dialect: str, place: str = ""):
        if dialect not in DIALECTS:
            raise ValueError(f"no documents' dialect {dialect!r}: {', '.join(DIALECTS)}")
        self.session, self.kind, self.dialect = session, kind, DIALECTS[dialect]
        self.engine = dialect
        self.place = place
        self.table = TABLE_PREFIX + kind.collection

    # -- words of the statements -------------------------------------------------------------------------------------
    def _q(self, name: str) -> str:
        q = self.dialect.quote
        return f"{q}{name}{q}"

    def _marks(self, n: int) -> str:
        return ", ".join([self.dialect.mark] * n)

    def _type(self, field: str) -> str:
        if field in self.kind.numbers:
            return self.dialect.number
        if field in (self.kind.key[0], self.kind.order):
            return self.dialect.keyed
        return self.dialect.text

    def _ready(self, conn) -> None:
        """Its table and indexes made where they are not (once in this process for each place)."""
        token = (self.place, self.dialect.name, self.table)
        if self.place and token in _READY:
            return
        t = self._q(self.table)
        cols = ", ".join(f"{self._q(f)} {self._type(f)}" for f in self.kind.fields)
        keyed = "CHAR(64)" if self.dialect.name != "sqlite" else "TEXT"
        cur = conn.cursor()
        cur.execute(f"CREATE TABLE IF NOT EXISTS {t} (doc_id {keyed} NOT NULL PRIMARY KEY, {cols}){self.dialect.table_tail}")
        cur.execute(f"CREATE INDEX IF NOT EXISTS {self._q(self.table + '_by_order')} ON {t} ({self._q(self.kind.order)})")
        cur.execute(f"CREATE INDEX IF NOT EXISTS {self._q(self.table + '_by_key')} ON {t} "
                    f"({self._q(self.kind.key[0])}, {self._q(self.kind.order)})")
        conn.commit()
        if self.place:
            if len(_READY) >= _READY_MOST:
                _READY.clear()
            _READY.add(token)

    def doc_id(self, doc: dict) -> str:
        import hashlib

        return hashlib.sha256(self.kind.id(doc).encode("utf-8")).hexdigest()

    def _cell(self, field: str, value):
        if field in self.kind.lists:
            return json.dumps(list(value or []))
        if value is None:
            return None
        if field in self.kind.numbers:
            return int(value)
        return value if isinstance(value, str) else str(value)

    def _doc(self, row) -> dict:
        d = dict(zip(self.kind.fields, row))
        for f in self.kind.lists:
            d[f] = json.loads(d[f] or "[]")
        for f in self.kind.numbers:
            if d[f] is not None:
                d[f] = int(d[f])
        return d

    def _where(self, where: dict | None, since, extra: list[str] | None = None) -> tuple[str, list]:
        sql, args = list(extra or ()), []
        for f, v in (where or {}).items():
            if f not in self.kind.fields:
                raise ValueError(f"{self.kind.name} has no field {f!r}")
            if isinstance(v, (list, tuple, set)):
                v = list(v)
                if not v:
                    sql.append("1 = 0")
                    continue
                sql.append(f"{self._q(f)} IN ({self._marks(len(v))})")
                args += [self._cell(f, x) for x in v]
            else:
                sql.append(f"{self._q(f)} = {self.dialect.mark}")
                args.append(self._cell(f, v))
        if since is not None:
            sql.append(f"{self._q(self.kind.order)} >= {self.dialect.mark}")
            args.append(since)
        return (" WHERE " + " AND ".join(sql)) if sql else "", args

    def _fields(self) -> str:
        return ", ".join(self._q(f) for f in self.kind.fields)

    # -- the calls -----------------------------------------------------------------------------------------------------
    def put(self, docs: Iterable[dict], replace: bool = False) -> int:
        """Store documents; one held already is kept (`replace`: replaced). Returns how many were new (replaced: how
        many were given). Each batch is one transaction; a failure is raised as the server said it, nothing kept of it."""
        docs = list(docs)
        if not docs:
            return 0
        d = self.dialect
        t, cols = self._q(self.table), ["doc_id", *self.kind.fields]
        tail = (d.replace.format(sets=", ".join(d.replace_column.format(c=self._q(f)) for f in self.kind.fields))
                if replace else d.keep)
        insert = f"INSERT INTO {t} ({', '.join(self._q(c) for c in cols)}) VALUES ({self._marks(len(cols))}){tail}"
        new = 0
        with self.session() as conn:
            self._ready(conn)
            for i in range(0, len(docs), PUT_BATCH):
                batch = docs[i:i + PUT_BATCH]
                rows = {}
                for doc in batch:  # (one key given twice: the last, as the others' stores keep it)
                    rows[self.doc_id(doc)] = (self.doc_id(doc), *(self._cell(f, doc.get(f)) for f in self.kind.fields))
                try:
                    cur = conn.cursor()
                    cur.execute(f"SELECT doc_id FROM {t} WHERE doc_id IN ({self._marks(len(rows))})", list(rows))
                    held = {str(r[0]) for r in cur.fetchall()}
                    cur.executemany(insert, list(rows.values()))
                    conn.commit()
                except Exception:
                    try:
                        conn.rollback()
                    except Exception:  # noqa: BLE001 - a connection gone: its failure is the one raised
                        pass
                    raise
                new += len(batch) if replace else sum(1 for k in rows if k not in held)
        return new

    def find(self, where: dict | None = None, since=None, limit: int | None = None) -> list[dict]:
        w, args = self._where(where, since)
        sql = f"SELECT {self._fields()} FROM {self._q(self.table)}{w} ORDER BY {self._q(self.kind.order)} DESC"
        if limit is not None:
            sql += f" LIMIT {int(limit)}"
        with self.session() as conn:
            self._ready(conn)
            cur = conn.cursor()
            cur.execute(sql, args)
            rows = cur.fetchall()
            conn.rollback()  # (a read: its transaction ended)
        return [self._doc(r) for r in rows]

    def newest(self, where: dict | None = None):
        w, args = self._where(where, None)
        with self.session() as conn:
            self._ready(conn)
            cur = conn.cursor()
            cur.execute(f"SELECT MAX({self._q(self.kind.order)}) FROM {self._q(self.table)}{w}", args)
            got = cur.fetchone()
            conn.rollback()
        value = got[0] if got else None
        return int(value) if value is not None and self.kind.order in self.kind.numbers else value

    def count(self, where: dict | None = None) -> int:
        w, args = self._where(where, None)
        with self.session() as conn:
            self._ready(conn)
            cur = conn.cursor()
            cur.execute(f"SELECT COUNT(*) FROM {self._q(self.table)}{w}", args)
            got = cur.fetchone()
            conn.rollback()
        return int(got[0] if got else 0)

    def every(self, where: dict | None = None, batch: int = 5000) -> Iterator[list[dict]]:
        """All documents (matching `where`) a batch at a time, by doc_id: each batch its own statement, from the last
        key read (never the whole table at once; nothing held between batches)."""
        after = None
        while True:
            extra = [f"doc_id > {self.dialect.mark}"] if after is not None else []
            w, args = self._where(where, None, extra)
            if after is not None:
                args = [after, *args]
            sql = (f"SELECT doc_id, {self._fields()} FROM {self._q(self.table)}{w} ORDER BY doc_id "
                   f"LIMIT {int(batch)}")
            with self.session() as conn:
                self._ready(conn)
                cur = conn.cursor()
                cur.execute(sql, args)
                rows = cur.fetchall()
                conn.rollback()
            if not rows:
                return
            after = str(rows[-1][0])
            yield [self._doc(r[1:]) for r in rows]
            if len(rows) < batch:
                return


def copy(src, dst, where: dict | None = None) -> tuple[int, int]:
    """Every document of `src` (matching `where`) into `dst` (kept where held: a copy run twice puts
    nothing twice). Returns (documents read, new in dst)."""
    read = new = 0
    for batch in src.every(where):
        read += len(batch)
        new += dst.put(batch)
    return read, new
