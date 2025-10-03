from __future__ import annotations

from typing import Iterable

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

from dspm.classify.engine import classify_text, classify_text_detailed
from dspm.classify.filters import apply_context_filters
from dspm.core.models import Evidence, Finding, ScanConfig
from .base import Scanner


class PostgresScanner(Scanner):
    def scan(self, target: str, config: ScanConfig) -> Iterable[Finding]:
        # target: postgres://user:pass@host:port/db:table1,table2
        if psycopg2 is None:
            return []
        try:
            conn_str, tables = target.split(":", 1)
            table_list = [t for t in tables.split(",") if t]
            conn = psycopg2.connect(conn_str)
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
            filtered = apply_context_filters(detailed, sample, table_name=table, db_engine="postgres")
            classifications = [f"{b}:{n}" for (b, n, _m) in filtered]
            if classifications:
                yield Finding(
                    id=f"pg:{table}",
                    resource=conn_str,
                    location=f"{conn_str}/{table}",
                    classifications=classifications,
                    evidence=[Evidence(snippet=sample[:200])],
                    severity="medium",
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


