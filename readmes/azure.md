Azure Blob Scanner Setup
========================

Requirements
------------
- `azure-storage-blob`
- Connection string

Quick steps
-----------
Target format: `<connection-string>|container/prefix`
```bash
# Sample connection string format
export AZURE_CONN="DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...;EndpointSuffix=core.windows.net"

# Scan a container or a prefix
ghostlight scan --scanner azure --target "$AZURE_CONN|container"
ghostlight scan --scanner azure --target "$AZURE_CONN|container/prefix" --format json --output azure.json
```


