PostgreSQL Scanner Setup
========================

Target format
-------------
`postgres://user:pass@host:5432/db:schema.table1,schema.table2`

Quick steps
-----------
```bash
ghostlight scan --scanner postgres --target "postgres://user:pass@db:5432/app:public.users,public.orders"
```

Notes
-----
- You can omit the tables to auto-discover (may scan many tables).
- Use `--list-tables` to preview tables and `--show-sql` to log queries.


