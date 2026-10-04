
import streamlit as st
import pandas as pd
import joblib
import re
import math
from urllib.parse import urlparse


# Load trained model
model = joblib.load("phishguard_model.pkl")


# Feature extraction function
def extract_features(url):

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    domain = parsed.netloc
    path = parsed.path
    query = parsed.query

    domain_without_port = domain.split(":")[0]

    # URL length
    url_length = len(url)

    # IP address
    has_ip_address = 1 if re.match(
        r"^(?:\d{1,3}\.){3}\d{1,3}$",
        domain_without_port
    ) else 0

    # Dot count
    dot_count = url.count(".")

    # HTTPS
    https_flag = 1 if parsed.scheme == "https" else 0

    # URL entropy
    if len(url) > 0:
        frequency = {}

        for char in url:
            frequency[char] = frequency.get(char, 0) + 1

        url_entropy = 0

        for count in frequency.values():
            probability = count / len(url)
            url_entropy -= probability * math.log2(probability)
    else:
        url_entropy = 0

    # Token count
    tokens = re.split(r"[/\-_.?=&:]+", url)
    tokens = [token for token in tokens if token]
    token_count = len(tokens)

    # Subdomain count
    domain_parts = domain_without_port.split(".")
    subdomain_count = max(len(domain_parts) - 2, 0)

    # Query parameters
    query_param_count = 0 if not query else len(query.split("&"))

    # TLD length
    tld = domain_parts[-1] if len(domain_parts) > 1 else ""
    tld_length = len(tld)

    # Path length
    path_length = len(path)

    # Hyphen in domain
    has_hyphen_in_domain = 1 if "-" in domain_without_port else 0

    # Number of digits
    number_of_digits = sum(char.isdigit() for char in url)

    # TLD popularity
    common_tlds = {
        "com", "org", "net", "edu", "gov",
        "in", "co", "uk", "de", "io"
    }

    tld_popularity = 1 if tld.lower() in common_tlds else 0

    # Suspicious file extension
    suspicious_extensions = (
        ".exe", ".scr", ".zip", ".rar",
        ".bat", ".cmd", ".msi", ".apk"
    )

    suspicious_file_extension = 1 if any(
        path.lower().endswith(ext)
        for ext in suspicious_extensions
    ) else 0

    # Domain name length
    domain_name_length = len(domain_without_port)

    # Percentage numeric characters
    percentage_numeric_chars = (
        number_of_digits / len(url) * 100
        if len(url) > 0 else 0
    )

    return [
        url_length,
        has_ip_address,
        dot_count,
        https_flag,
        url_entropy,
        token_count,
        subdomain_count,
        query_param_count,
        tld_length,
        path_length,
        has_hyphen_in_domain,
        number_of_digits,
        tld_popularity,
        suspicious_file_extension,
        domain_name_length,
        percentage_numeric_chars
    ]


# Page title
st.title("🛡️ PhishGuard")
st.write("Machine Learning Based Phishing URL Detection")

st.divider()

# URL input
url = st.text_input(
    "Enter a URL to check:",
    placeholder="https://example.com"
)


# Prediction button
if st.button("Check URL"):

    if url.strip() == "":
        st.warning("Please enter a URL.")

    else:

        features = extract_features(url)

        feature_columns = [
            "url_length",
            "has_ip_address",
            "dot_count",
            "https_flag",
            "url_entropy",
            "token_count",
            "subdomain_count",
            "query_param_count",
            "tld_length",
            "path_length",
            "has_hyphen_in_domain",
            "number_of_digits",
            "tld_popularity",
            "suspicious_file_extension",
            "domain_name_length",
            "percentage_numeric_chars"
        ]

        features_df = pd.DataFrame(
            [features],
            columns=feature_columns
        )

        prediction = model.predict(features_df)[0]

        probability = model.predict_proba(features_df)[0]

        if prediction == 0:

            st.error("⚠️ Phishing URL")

            st.write(
                f"Phishing probability: {probability[0] * 100:.2f}%"
            )

        else:

            st.success("✅ Legitimate URL")

            st.write(
                f"Legitimate probability: {probability[1] * 100:.2f}%"
            )
