Azure Blob Scanner Setup
========================

Requirements
------------
- `azure-storage-blob`
- Connection string

Scan examples
-------------
Target format: `<connection-string>|container/prefix`
```bash
ghostlight scan --scanner azure --target "DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...;EndpointSuffix=core.windows.net|container/prefix"
```


