from __future__ import annotations

from typing import Iterable
from urllib.parse import urlparse

try:
    # Prefer psycopg3 if available
    import psycopg as psycopg2  # type: ignore
except Exception:  # pragma: no cover
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
from ghostlight.classify.ai_filter import ai_classify_detection
from ghostlight.core.models import Evidence, Finding, ScanConfig
from ghostlight.utils.snippets import earliest_line_and_snippet
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
                sql_sample = f'SELECT * FROM "{schema}"."{table}" LIMIT {config.sample_rows}'
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
            # Optionally apply AI verification
            import os as _os
            ai_mode = _os.getenv("GHOSTLIGHT_AI_FILTER", "auto")
            if ai_mode != "off" and detailed:
                ai_verified = []
                for bucket, pattern_name, matches in filtered:
                    matched_value = str(matches[0]) if matches else ""
                    is_tp, _reason = ai_classify_detection(
                        pattern_name=pattern_name,
                        matched_value=matched_value,
                        sample_text=sample,
                        table_name=f"{schema}.{table}",
                        db_engine="postgres",
                        column_names=columns,
                        use_ai=ai_mode
                    )
                    if is_tp:
                        ai_verified.append((bucket, pattern_name, matches))
                filtered = ai_verified
            earliest_line, snippet_line = earliest_line_and_snippet(sample, filtered)
            classifications = [f"{b}:{n}" for (b, n, _m) in filtered]
            if classifications:
                yield Finding(
                    id=f"pg:{schema}.{table}",
                    resource=dsn,
                    location=f"{dsn}/{schema}.{table}:{earliest_line or 1}",
                    classifications=classifications,
                    evidence=[Evidence(snippet=snippet_line)],
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
        # Direct DSN support: mysql://user:pass@host:port/db
        if pymysql is None:
            return []
        dsn = target
        try:
            parsed = urlparse(dsn)
            if parsed.scheme not in {"mysql"}:
                # If user passed bare DSN without scheme, still try pymysql with target
                parsed = None  # type: ignore
            host = (parsed.hostname if parsed else None) or ""
            port = (parsed.port if parsed else None) or 3306
            user = (parsed.username if parsed else None) or ""
            password = (parsed.password if parsed else None) or ""
            db_name = (parsed.path.lstrip("/") if parsed else None) or ""
        except Exception:
            host = ""; port = 3306; user = ""; password = ""; db_name = ""

        # Connect
        try:
            conn = pymysql.connect(host=host, port=port, user=user, password=password, database=db_name, connect_timeout=10)
        except Exception:
            return []
        cur = conn.cursor()

        # Connection metadata
        server_version = ""
        try:
            cur.execute("SELECT VERSION()")
            server_version = str(cur.fetchone()[0])
        except Exception:
            server_version = ""

        # Discover tables in current database
        try:
            sql_list = (
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE' ORDER BY table_name"
            )
            if config.show_sql:
                from ghostlight.utils.logging import get_logger
                get_logger(__name__).info(f"SQL: {sql_list}")
            cur.execute(sql_list)
            tables = [row[0] for row in cur.fetchall()]
        except Exception:
            tables = []
        if config.list_tables and tables:
            from ghostlight.utils.logging import get_logger
            get_logger(__name__).info("Tables: " + ", ".join([str(t) for t in tables]))

        for table in tables:
            try:
                # Row count
                sql_count = f"SELECT COUNT(*) FROM `{table}`"
                if config.show_sql:
                    from ghostlight.utils.logging import get_logger
                    get_logger(__name__).info(f"SQL: {sql_count}")
                cur.execute(sql_count)
                row_count = int(cur.fetchone()[0])

                # Sample rows
                sql_sample = f"SELECT * FROM `{table}` LIMIT {config.sample_rows}"
                if config.show_sql:
                    from ghostlight.utils.logging import get_logger
                    get_logger(__name__).info(f"SQL: {sql_sample}")
                cur.execute(sql_sample)
                rows = cur.fetchall()

                # Columns
                sql_cols = (
                    "SELECT COLUMN_NAME FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = %s ORDER BY ORDINAL_POSITION"
                )
                if config.show_sql:
                    from ghostlight.utils.logging import get_logger
                    get_logger(__name__).info(f"SQL: {sql_cols} [params: {table}]")
                cur.execute(sql_cols, (table,))
                columns = [r[0] for r in cur.fetchall()]

                # Table size estimate
                sql_size = (
                    "SELECT (DATA_LENGTH + INDEX_LENGTH) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = %s"
                )
                if config.show_sql:
                    from ghostlight.utils.logging import get_logger
                    get_logger(__name__).info(f"SQL: {sql_size} [params: {table}]")
                cur.execute(sql_size, (table,))
                size_row = cur.fetchone()
                size_bytes = int(size_row[0]) if size_row and size_row[0] is not None else 0
            except Exception:
                continue

            sample = "\n".join(str(r) for r in rows)[: config.sample_bytes]
            detailed = classify_text_detailed(sample)
            filtered = apply_context_filters(detailed, sample, table_name=table, db_engine="mysql")
            # Optionally apply AI verification
            import os as _os
            ai_mode = _os.getenv("GHOSTLIGHT_AI_FILTER", "auto")
            if ai_mode != "off" and detailed:
                ai_verified = []
                for bucket, pattern_name, matches in filtered:
                    matched_value = str(matches[0]) if matches else ""
                    is_tp, _reason = ai_classify_detection(
                        pattern_name=pattern_name,
                        matched_value=matched_value,
                        sample_text=sample,
                        table_name=table,
                        db_engine="mysql",
                        column_names=columns,
                        use_ai=ai_mode
                    )
                    if is_tp:
                        ai_verified.append((bucket, pattern_name, matches))
                filtered = ai_verified
            earliest_line, snippet_line = earliest_line_and_snippet(sample, filtered)
            classifications = [f"{b}:{n}" for (b, n, _m) in filtered]
            if classifications:
                yield Finding(
                    id=f"mysql:{db_name}.{table}",
                    resource=dsn,
                    location=f"{dsn}/{table}:{earliest_line or 1}",
                    classifications=classifications,
                    evidence=[Evidence(snippet=snippet_line)],
                    severity="medium",
                    metadata={
                        "db_engine": "mysql",
                        "server_version": server_version,
                        "database": db_name,
                        "host": host,
                        "port": str(port),
                        "schema": db_name,
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
                    data_source="mysql",
                    profile=db_name or host,
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
            # Optionally apply AI verification
            import os as _os
            ai_mode = _os.getenv("GHOSTLIGHT_AI_FILTER", "auto")
            if ai_mode != "off" and detailed:
                ai_verified = []
                for bucket, pattern_name, matches in filtered:
                    matched_value = str(matches[0]) if matches else ""
                    is_tp, _reason = ai_classify_detection(
                        pattern_name=pattern_name,
                        matched_value=matched_value,
                        sample_text=sample,
                        table_name=coll,
                        db_engine="mongodb",
                        column_names=None,
                        use_ai=ai_mode
                    )
                    if is_tp:
                        ai_verified.append((bucket, pattern_name, matches))
                filtered = ai_verified
            earliest_line, snippet_line = earliest_line_and_snippet(sample, filtered)
            classifications = [f"{b}:{n}" for (b, n, _m) in filtered]
            if classifications:
                yield Finding(
                    id=f"mongo:{coll}",
                    resource=dsn,
                    location=f"{dsn}/{coll}:{earliest_line or 1}",
                    classifications=classifications,
                    evidence=[Evidence(snippet=snippet_line)],
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
            # Optionally apply AI verification
            import os as _os
            ai_mode = _os.getenv("GHOSTLIGHT_AI_FILTER", "auto")
            if ai_mode != "off" and detailed:
                ai_verified = []
                for bucket, pattern_name, matches in filtered:
                    matched_value = str(matches[0]) if matches else ""
                    is_tp, _reason = ai_classify_detection(
                        pattern_name=pattern_name,
                        matched_value=matched_value,
                        sample_text=text,
                        table_name=str(k),
                        db_engine="redis",
                        column_names=None,
                        use_ai=ai_mode
                    )
                    if is_tp:
                        ai_verified.append((bucket, pattern_name, matches))
                filtered = ai_verified
            earliest_line, snippet_line = earliest_line_and_snippet(text, filtered)
            classifications = [f"{b}:{n}" for (b, n, _m) in filtered]
            if classifications:
                yield Finding(
                    id=f"redis:{k}",
                    resource=target,
                    location=f"{target}/{k}:{earliest_line or 1}",
                    classifications=classifications,
                    evidence=[Evidence(snippet=snippet_line)],
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
            # Optionally apply AI verification
            import os as _os
            ai_mode = _os.getenv("GHOSTLIGHT_AI_FILTER", "auto")
            if ai_mode != "off" and detailed:
                ai_verified = []
                for bucket, pattern_name, matches in filtered:
                    matched_value = str(matches[0]) if matches else ""
                    is_tp, _reason = ai_classify_detection(
                        pattern_name=pattern_name,
                        matched_value=matched_value,
                        sample_text=sample,
                        table_name=coll,
                        db_engine="firestore",
                        column_names=None,
                        use_ai=ai_mode
                    )
                    if is_tp:
                        ai_verified.append((bucket, pattern_name, matches))
                filtered = ai_verified
            earliest_line, snippet_line = earliest_line_and_snippet(sample, filtered)
            classifications = [f"{b}:{n}" for (b, n, _m) in filtered]
            if classifications:
                yield Finding(
                    id=f"firebase:{coll}",
                    resource=project,
                    location=f"firestore://{project}/{coll}:{earliest_line or 1}",
                    classifications=classifications,
                    evidence=[Evidence(snippet=snippet_line)],
                    severity="medium",
                )


