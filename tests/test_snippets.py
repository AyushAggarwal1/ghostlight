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


