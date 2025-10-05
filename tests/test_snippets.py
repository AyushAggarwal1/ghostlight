from ghostlight.utils.snippets import earliest_line_and_snippet


def test_earliest_line_and_snippet_simple():
    text = """line1
line2 secret-abc
line3
"""
    filtered = [("SECRETS", "Test", ["secret-abc"]) ]
    ln, snippet = earliest_line_and_snippet(text, filtered)
    assert ln == 2
    assert snippet.strip() == "line2 secret-abc"


def test_earliest_line_and_snippet_multiple():
    text = """a@b.com
foo
key_123
"""
    filtered = [
        ("GDPR", "PII.Email", ["a@b.com"]),
        ("SECRETS", "Key", ["key_123"]),
    ]
    ln, snippet = earliest_line_and_snippet(text, filtered)
    assert ln == 1
    assert snippet.strip() == "a@b.com"


def test_earliest_line_and_snippet_private_key():
    text = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAx+zU3dF+KxQ0CzNQgZG6YXjuei83eT7Xm3zv4d0YZFf+036P
-----END RSA PRIVATE KEY-----
"""
    filtered = [("SECRETS", "Secrets.RSA.PrivateKey", ["-----BEGIN RSA PRIVATE KEY-----"]),
                ("SECRETS", "Secrets.OpenSSH.PrivateKey", ["-----BEGIN OPENSSH PRIVATE KEY-----"]),
                ("SECRETS", "Secrets.PGP.PrivateKey", ["-----BEGIN PGP PRIVATE KEY BLOCK-----"]),
                ]
    ln, snippet = earliest_line_and_snippet(text, filtered)
    assert ln == 1
    assert snippet.strip() == "-----BEGIN RSA PRIVATE KEY-----" 

def test_earliest_line_and_snippet_private_key_multiple():
    text = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAx+zU3dF+KxQ0CzNQgZG6YXjuei83eT7Xm3zv4d0YZFf+036P
-----END RSA PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
MIIEpAIBAAKCAQEAx+zU3dF+KxQ0CzNQgZG6YXjuei83eT7Xm3zv4d0YZFf+036P
-----END OPENSSH PRIVATE KEY-----
-----BEGIN PGP PRIVATE KEY BLOCK-----
MIIEpAIBAAKCAQEAx+zU3dF+KxQ0CzNQgZG6YXjuei83eT7Xm3zv4d0YZFf+036P
-----END PGP PRIVATE KEY BLOCK-----
"""
    filtered = [("SECRETS", "Secrets.RSA.PrivateKey", ["-----BEGIN RSA PRIVATE KEY-----"]),
                ("SECRETS", "Secrets.OpenSSH.PrivateKey", ["-----BEGIN OPENSSH PRIVATE KEY-----"]),
                ("SECRETS", "Secrets.PGP.PrivateKey", ["-----BEGIN PGP PRIVATE KEY BLOCK-----"]),
                ]
    ln, snippet = earliest_line_and_snippet(text, filtered)
    assert ln == 1
    assert snippet.strip() == "-----BEGIN RSA PRIVATE KEY-----" 
    