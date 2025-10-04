PostgreSQL Scanner Setup
========================

Target format
-------------
`postgres://user:pass@host:5432/db:schema.table1,schema.table2`

Examples
--------
```bash
ghostlight scan --scanner postgres --target "postgres://user:pass@db:5432/app:public.users,public.orders"
```


