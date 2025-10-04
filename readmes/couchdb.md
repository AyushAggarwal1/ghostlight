CouchDB Scanner Setup
=====================

Target format
-------------
`http[s]://user:pass@host:5984:db1,db2`

Credentials
-----------
1. Ensure your CouchDB allows the user to read the target databases.
2. Build a URL like:
   - `http://admin:password@localhost:5984:users,orders`

Run a scan
----------
```bash
ghostlight scan --scanner couchdb --target "http://admin:pass@couchdb:5984:users,orders"
```

Notes
-----
- You can pass multiple databases separated by commas.


