from __future__ import annotations

from typing import Iterable

try:
    from azure.storage.blob import BlobServiceClient  # type: ignore
except Exception:  # pragma: no cover
    BlobServiceClient = None

from ghostlight.classify.engine import classify_text
from ghostlight.core.models import Evidence, Finding, ScanConfig
from .base import Scanner


class AzureBlobScanner(Scanner):
    def scan(self, target: str, config: ScanConfig) -> Iterable[Finding]:
        # target: connection_string:container[/prefix]
        if BlobServiceClient is None:
            return []
        try:
            connection_string, rest = target.split("|", 1)
            if "/" in rest:
                container, prefix = rest.split("/", 1)
            else:
                container, prefix = rest, ""
        except ValueError:
            return []

        client = BlobServiceClient.from_connection_string(connection_string)
        container_client = client.get_container_client(container)
        for blob in container_client.list_blobs(name_starts_with=prefix):
            if blob.size and blob.size > config.max_file_mb * 1024 * 1024:
                continue
            try:
                stream = container_client.download_blob(blob.name, offset=0, length=config.sample_bytes)
                data = stream.readall()
                text = data.decode("utf-8", errors="ignore")
            except Exception:
                continue
            labels = classify_text(text)
            classifications = [
                f"GDPR:{l}" for l in labels.get("GDPR", [])
            ] + [
                f"HIPAA:{l}" for l in labels.get("HIPAA", [])
            ] + [
                f"PCI:{l}" for l in labels.get("PCI", [])
            ] + [
                f"SECRETS:{l}" for l in labels.get("SECRETS", [])
            ]
            if not classifications:
                continue
            yield Finding(
                id=f"azure:{container}/{blob.name}",
                resource=container,
                location=f"azure://{container}/{blob.name}",
                classifications=classifications,
                evidence=[Evidence(snippet=text[:200])],
                severity="medium",
            )


