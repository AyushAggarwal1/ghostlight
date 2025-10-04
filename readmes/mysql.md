MySQL Scanner Setup
===================

Target format
-------------
`mysql://user:pass@host:3306/db:table1,table2`

Quick steps
-----------
```bash
ghostlight scan --scanner mysql --target "mysql://user:pass@db:3306/app:users,orders"
```

Notes
-----
- You can omit the tables to auto-discover from current database.
- Use `--list-tables` (RDS) or MySQL client to plan your table list.


