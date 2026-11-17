TOKENIZER_VERSION = "synthetic-whitespace-v1"


def estimate_tokens(text: str) -> int:
    """Exact synthetic tokens: Unicode whitespace-delimited words, empty input = 0."""
    return len(text.split())
