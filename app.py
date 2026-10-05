from flask import Flask, render_template, request
from urllib.parse import urlparse
import re
import ipaddress

app = Flask(__name__)


# -----------------------------------
# Check if domain is an IP address
# -----------------------------------
def is_ip_address(domain):
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


# -----------------------------------
# Advanced URL Feature Extraction
# -----------------------------------
def extract_features(url):

    # Add scheme if user doesn't enter one
    normalized_url = url

    if not re.match(r"^https?://", normalized_url, re.IGNORECASE):
        normalized_url = "http://" + normalized_url

    parsed = urlparse(normalized_url)

    domain = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    keywords = [
        "login",
        "verify",
        "update",
        "secure",
        "account",
        "password",
        "signin",
        "bank",
        "confirm"
    ]

    found_keywords = [
        word for word in keywords
        if word in normalized_url.lower()
    ]

    # Count query parameters
    query_params = 0

    if query:
        query_params = len(query.split("&"))

    # Count subdomains
    domain_parts = domain.split(".") if domain else []

    subdomains = max(0, len(domain_parts) - 2)

    features = {
        "url_length": len(normalized_url),
        "domain_length": len(domain),
        "num_dots": domain.count("."),
        "num_hyphens": domain.count("-"),
        "num_subdomains": subdomains,
        "num_special_chars": len(
            re.findall(r"[^a-zA-Z0-9]", normalized_url)
        ),
        "has_https": int(parsed.scheme.lower() == "https"),
        "has_ip": int(is_ip_address(domain)),
        "has_at_symbol": int("@" in normalized_url),
        "has_suspicious_keyword": int(len(found_keywords) > 0),
        "num_query_params": query_params,
        "path_length": len(path),
        "suspicious_keywords": found_keywords
    }

    return features


# -----------------------------------
# URL Risk Analysis
# -----------------------------------
def analyze_url(url):

    features = extract_features(url)

    risk_score = 0
    warnings = []

    # HTTPS
    if features["has_https"] == 0:
        risk_score += 2
        warnings.append(
            "Website does not use HTTPS."
        )

    # IP address
    if features["has_ip"] == 1:
        risk_score += 3
        warnings.append(
            "URL uses an IP address instead of a domain name."
        )

    # @ symbol
    if features["has_at_symbol"] == 1:
        risk_score += 3
        warnings.append(
            "URL contains an @ symbol."
        )

    # Multiple hyphens
    if features["num_hyphens"] >= 2:
        risk_score += 2
        warnings.append(
            "Domain contains multiple hyphens."
        )

    # Long URL
    if features["url_length"] > 100:
        risk_score += 1
        warnings.append(
            "URL is unusually long."
        )

    # Many subdomains
    if features["num_subdomains"] >= 3:
        risk_score += 1
        warnings.append(
            "URL contains multiple subdomains."
        )

    # Suspicious keywords
    if features["has_suspicious_keyword"] == 1:
        risk_score += 1

        warnings.append(
            "URL contains security-related keywords: "
            + ", ".join(features["suspicious_keywords"])
        )

    # Many query parameters
    if features["num_query_params"] >= 4:
        risk_score += 1
        warnings.append(
            "URL contains multiple query parameters."
        )

    # Final classification
    if risk_score >= 5:
        status = "Potentially Suspicious"

    elif risk_score >= 2:
        status = "Needs Caution"

    else:
        status = "Likely Safe"

    return status, risk_score, warnings, features


# -----------------------------------
# Home Page
# -----------------------------------
@app.route("/")
def home():
    return render_template("index.html")


# -----------------------------------
# Scan URL
# -----------------------------------
@app.route("/scan", methods=["POST"])
def scan():

    url = request.form.get("url", "").strip()

    if not url:
        return {
            "status": "Invalid",
            "score": 0,
            "warnings": ["Please enter a URL."],
            "features": {}
        }

    status, score, warnings, features = analyze_url(url)

    return {
        "status": status,
        "score": score,
        "warnings": warnings,
        "features": features
    }


# -----------------------------------
# Run Flask Server
# -----------------------------------
if __name__ == "__main__":
    app.run(debug=True)