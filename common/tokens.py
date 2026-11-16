def estimate_tokens(text: str) -> int:
    """About 4 characters per token. Same function in the app and the WAF."""
    return max(1, len(text) // 4)