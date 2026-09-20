from urllib.parse import urlparse
import ipaddress


def has_ip_address(url):
    """
    Check whether the URL uses an IP address instead of a domain name.
    """

    try:
        hostname = urlparse(url).hostname

        if hostname is None:
            return -1

        ipaddress.ip_address(hostname)
        return 1

    except ValueError:
        return -1


def url_length(url):
    """
    Classify URL length according to the dataset's
    three-value feature representation.
    """

    length = len(url)

    if length < 54:
        return 1
    elif length <= 75:
        return 0
    else:
        return -1


def has_at_symbol(url):
    """
    Check whether the URL contains '@'.
    """

    return -1 if "@" in url else 1


def has_prefix_suffix(url):
    """
    Check whether the domain contains a hyphen.
    """

    try:
        hostname = urlparse(url).hostname

        if hostname is None:
            return -1

        return -1 if "-" in hostname else 1

    except Exception:
        return -1


def count_subdomains(url):
    """
    Estimate the number of subdomains.
    """

    hostname = urlparse(url).hostname

    if hostname is None:
        return -1

    parts = hostname.split(".")

    if len(parts) <= 2:
        return 1
    elif len(parts) == 3:
        return 0
    else:
        return -1


def has_https(url):
    """
    Check whether HTTPS is used.
    """

    return 1 if urlparse(url).scheme == "https" else -1


def extract_basic_features(url):

    features = {
        "having_IP_Address": has_ip_address(url),
        "URL_Length": url_length(url),
        "Shortining_Service": has_shortening_service(url),
        "having_At_Symbol": has_at_symbol(url),
        "double_slash_redirecting": has_double_slash_redirecting(url),
        "Prefix_Suffix": has_prefix_suffix(url),
        "having_Sub_Domain": count_subdomains(url),
        "HTTPS_token": has_https_token(url),
        "SSLfinal_State": has_https(url)
    }

    return features

import re


def has_shortening_service(url):
    """
    Detect common URL-shortening services.
    """

    shortening_services = [
        "bit.ly",
        "goo.gl",
        "tinyurl.com",
        "t.co",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "cutt.ly",
        "rb.gy",
        "shorturl.at"
    ]

    hostname = urlparse(url).hostname

    if hostname is None:
        return -1

    for service in shortening_services:
        if service in hostname.lower():
            return -1

    return 1


def has_double_slash_redirecting(url):
    """
    Check for '//' appearing in the URL path.
    """

    try:
        path = urlparse(url).path

        return -1 if "//" in path else 1

    except Exception:
        return -1


def has_https_token(url):
    """
    Check whether 'https' appears inside the hostname.
    This is different from simply checking the URL scheme.
    """

    hostname = urlparse(url).hostname

    if hostname is None:
        return -1

    return -1 if "https" in hostname.lower() else 1


def suspicious_url_characters(url):
    """
    Check for a high number of suspicious characters.
    """

    suspicious = re.findall(r"[@?=&%]", url)

    return -1 if len(suspicious) >= 3 else 1