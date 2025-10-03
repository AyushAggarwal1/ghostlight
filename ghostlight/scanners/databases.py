from __future__ import annotations

from typing import Iterable
from urllib.parse import urlparse

try:
    import psycopg2  # type: ignore
except Exception:  # pragma: no cover
    psycopg2 = None
try:
    import pymongo  # type: ignore
except Exception:  # pragma: no cover
    pymongo = None
try:
    import pymysql  # type: ignore
except Exception:  # pragma: no cover
    pymysql = None
try:
    import redis as redis_lib  # type: ignore
except Exception:  # pragma: no cover
    redis_lib = None
try:
    import firebase_admin  # type: ignore
    from firebase_admin import firestore  # type: ignore
except Exception:  # pragma: no cover
    firebase_admin = None
    firestore = None

from ghostlight.classify.engine import classify_text, classify_text_detailed
from ghostlight.classify.filters import apply_context_filters
from ghostlight.core.models import Evidence, Finding, ScanConfig
from .base import Scanner


class PostgresScanner(Scanner):
    def scan(self, target: str, config: ScanConfig) -> Iterable[Finding]:
        # Accept full DSN URL (preferred): postgresql://user:pass@host:port/db?params
        # Backward-compatibility: if no scheme present, original "dsn:table1,table2" style is ignored; we auto-discover tables
        if psycopg2 is None:
            return []
        # Determine DSN
        dsn = target
        try:
            parsed = urlparse(target)
            if not parsed.scheme:
                # No scheme; treat entire target as DSN anyway
                dsn = target
        except Exception:
            dsn = target

        # Connect
        try:
            conn = psycopg2.connect(dsn)
        except Exception:
            return []
        cur = conn.cursor()

        # Connection-level metadata
        db_name = ""
        server_version = ""
        host = ""
        port = ""
        try:
            cur.execute("SELECT current_database()")
            db_name = cur.fetchone()[0] or ""
        except Exception:
            db_name = ""
        try:
            cur.execute("SHOW server_version")
            server_version = cur.fetchone()[0] or ""
        except Exception:
            server_version = ""
        try:
            parsed = urlparse(dsn)
            host = parsed.hostname or ""
            port = str(parsed.port or "")
        except Exception:
            host = ""; port = ""

        # Discover tables (schema, table)
        try:
            sql_list = (
                "SELECT table_schema, table_name FROM information_schema.tables "
                "WHERE table_type = 'BASE TABLE' AND table_schema NOT IN ('pg_catalog','information_schema') "
                "ORDER BY table_schema, table_name"
            )
            if config.show_sql:
                from ghostlight.utils.logging import get_logger
                get_logger(__name__).info(f"SQL: {sql_list}")
            cur.execute(sql_list)
            discovered = [(row[0], row[1]) for row in cur.fetchall()]
        except Exception:
            discovered = []

        if config.list_tables and discovered:
            from ghostlight.utils.logging import get_logger
            get_logger(__name__).info("Tables: " + ", ".join([f"{s}.{t}" for s, t in discovered]))

        for schema, table in discovered:
            try:
                # Row count
                sql_count = f'SELECT COUNT(*) FROM "{schema}"."{table}"'
                if config.show_sql:
                    from ghostlight.utils.logging import get_logger
                    get_logger(__name__).info(f"SQL: {sql_count}")
                cur.execute(sql_count)
                row_count = int(cur.fetchone()[0])

                # Sample rows
                sql_sample = f'SELECT * FROM "{schema}"."{table}" LIMIT 100'
                if config.show_sql:
                    from ghostlight.utils.logging import get_logger
                    get_logger(__name__).info(f"SQL: {sql_sample}")
                cur.execute(sql_sample)
                rows = cur.fetchall()

                # Columns
                sql_cols = (
                    "SELECT column_name FROM information_schema.columns WHERE table_schema = %s AND table_name = %s ORDER BY ordinal_position"
                )
                if config.show_sql:
                    from ghostlight.utils.logging import get_logger
                    get_logger(__name__).info(f"SQL: {sql_cols} [params: {schema}, {table}]")
                cur.execute(sql_cols, (schema, table))
                columns = [r[0] for r in cur.fetchall()]

                # Table size in bytes (includes indexes)
                sql_size = "SELECT pg_total_relation_size(%s)"
                relname = f'"{schema}"."{table}"'
                if config.show_sql:
                    from ghostlight.utils.logging import get_logger
                    get_logger(__name__).info(f"SQL: {sql_size} [params: {relname}]")
                cur.execute(sql_size, (relname,))
                size_bytes = int(cur.fetchone()[0])
            except Exception:
                continue

            sample = "\n".join(str(r) for r in rows)[: config.sample_bytes]
            detailed = classify_text_detailed(sample)
            filtered = apply_context_filters(detailed, sample, table_name=f"{schema}.{table}", db_engine="postgres")
            classifications = [f"{b}:{n}" for (b, n, _m) in filtered]
            if classifications:
                yield Finding(
                    id=f"pg:{schema}.{table}",
                    resource=dsn,
                    location=f"{dsn}/{schema}.{table}",
                    classifications=classifications,
                    evidence=[Evidence(snippet=sample[:200])],
                    severity="medium",
                    metadata={
                        "db_engine": "postgresql",
                        "server_version": server_version,
                        "database": db_name,
                        "host": host,
                        "port": port,
                        "schema": schema,
                        "table_name": table,
                        "row_count": str(row_count),
                        "column_count": str(len(columns)),
                        "columns": ",".join(columns[:10]),
                        "size_bytes": str(size_bytes),
                        "sampled_rows": str(len(rows)),
                        "count_sql": sql_count,
                        "sample_sql": sql_sample,
                        "columns_sql": sql_cols,
                        "size_sql": sql_size,
                    },
                    data_source="postgres",
                    profile=db_name or host,
                )
        cur.close()
        conn.close()


class MySQLScanner(Scanner):
    def scan(self, target: str, config: ScanConfig) -> Iterable[Finding]:
        # target: mysql://user:pass@host:port/db:table1,table2
        if pymysql is None:
            return []
        try:
            conn_str, tables = target.split(":", 1)
            table_list = [t for t in tables.split(",") if t]
            conn = pymysql.connect(host="", user="", password="")  # Placeholder: parse DSN as needed
        except Exception:
            return []
        cur = conn.cursor()
        for table in table_list:
            try:
                cur.execute(f"SELECT * FROM {table} LIMIT 100")
                rows = cur.fetchall()
            except Exception:
                continue
            sample = "\n".join(str(r) for r in rows)[: config.sample_bytes]
            detailed = classify_text_detailed(sample)
            filtered = apply_context_filters(detailed, sample, table_name=table, db_engine="mysql")
            classifications = [f"{b}:{n}" for (b, n, _m) in filtered]
            if classifications:
                yield Finding(
                    id=f"mysql:{table}",
                    resource=conn_str,
                    location=f"{conn_str}/{table}",
                    classifications=classifications,
                    evidence=[Evidence(snippet=sample[:200])],
                    severity="medium",
                )
        cur.close()
        conn.close()


class MongoScanner(Scanner):
    def scan(self, target: str, config: ScanConfig) -> Iterable[Finding]:
        # target: mongodb://host/db:collection1,collection2
        if pymongo is None:
            return []
        try:
            dsn, collections = target.split(":", 1)
            coll_list = [c for c in collections.split(",") if c]
            client = pymongo.MongoClient(dsn)
            dbname = client.get_default_database().name
            db = client[dbname]
        except Exception:
            return []
        for coll in coll_list:
            try:
                docs = list(db[coll].find().limit(50))
            except Exception:
                continue
            sample = "\n".join(str(d) for d in docs)[: config.sample_bytes]
            detailed = classify_text_detailed(sample)
            filtered = apply_context_filters(detailed, sample, table_name=coll, db_engine="mongodb")
            classifications = [f"{b}:{n}" for (b, n, _m) in filtered]
            if classifications:
                yield Finding(
                    id=f"mongo:{coll}",
                    resource=dsn,
                    location=f"{dsn}/{coll}",
                    classifications=classifications,
                    evidence=[Evidence(snippet=sample[:200])],
                    severity="medium",
                )
        client.close()


class RedisScanner(Scanner):
    def scan(self, target: str, config: ScanConfig) -> Iterable[Finding]:
        # target: redis://host:port/db
        if redis_lib is None:
            return []
        try:
            r = redis_lib.from_url(target)
            keys = list(r.scan_iter(match="*", count=1000))[:200]
        except Exception:
            return []
        for k in keys:
            try:
                v = r.get(k)
                if v is None:
                    continue
                text = v.decode("utf-8", errors="ignore")[: config.sample_bytes]
            except Exception:
                continue
            detailed = classify_text_detailed(text)
            filtered = apply_context_filters(detailed, text, db_engine="redis")
            classifications = [f"{b}:{n}" for (b, n, _m) in filtered]
            if classifications:
                yield Finding(
                    id=f"redis:{k}",
                    resource=target,
                    location=f"{target}/{k}",
                    classifications=classifications,
                    evidence=[Evidence(snippet=text[:200])],
                    severity="medium",
                )


class FirebaseScanner(Scanner):
    def scan(self, target: str, config: ScanConfig) -> Iterable[Finding]:
        # target: firestore:project_id:collection1,collection2
        if firebase_admin is None or firestore is None:
            return []
        try:
            _, project, collections = target.split(":", 2)
            if not firebase_admin._apps:
                firebase_admin.initialize_app()
            db = firestore.client(project=project)
            coll_list = [c for c in collections.split(",") if c]
        except Exception:
            return []
        for coll in coll_list:
            try:
                docs = db.collection(coll).limit(50).stream()
                rows = [d.to_dict() for d in docs]
            except Exception:
                continue
            sample = "\n".join(str(r) for r in rows)[: config.sample_bytes]
            detailed = classify_text_detailed(sample)
            filtered = apply_context_filters(detailed, sample, table_name=coll, db_engine="firestore")
            classifications = [f"{b}:{n}" for (b, n, _m) in filtered]
            if classifications:
                yield Finding(
                    id=f"firebase:{coll}",
                    resource=project,
                    location=f"firestore://{project}/{coll}",
                    classifications=classifications,
                    evidence=[Evidence(snippet=sample[:200])],
                    severity="medium",
                )


