"""Server's delta-seconds Retry-After format, independent of Locust."""
import math


def retry_delay(response):
    if response.status_code!=429:return 0.0
    try:value=float(response.headers.get('Retry-After','0'))
    except (TypeError,ValueError):return 0.0
    return value if math.isfinite(value) and value>0 else 0.0
