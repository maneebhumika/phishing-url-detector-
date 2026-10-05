from urllib.parse import urlparse
import re


def extract_features(url):
    parsed = urlparse(url)

    features = {
        "url_length": len(url),
        "hostname_length": len(parsed.netloc),
        "path_length": len(parsed.path),
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "at_count": url.count("@"),
        "question_count": url.count("?"),
        "equal_count": url.count("="),
        "slash_count": url.count("/"),
        "https": 1 if parsed.scheme == "https" else 0,
        "ip_address": 1 if re.match(
            r"^(?:\d{1,3}\.){3}\d{1,3}$",
            parsed.hostname or ""
        ) else 0
    }

    return features
