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


UCI_FEATURES = [
    "having_IP_Address",
    "URL_Length",
    "Shortining_Service",
    "having_At_Symbol",
    "double_slash_redirecting",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "SSLfinal_State",
    "Domain_registration_length",
    "Favicon",
    "port",
    "HTTPS_token",
    "Request_URL",
    "URL_of_Anchor",
    "Links_in_tags",
    "SFH",
    "Submitting_to_email",
    "Abnormal_URL",
    "Redirect",
    "on_mouseover",
    "RightClick",
    "popUpWindow",
    "Iframe",
    "age_of_domain",
    "DNSRecord",
    "web_traffic",
    "Page_Rank",
    "Google_Index",
    "Links_pointing_to_page",
    "Statistical_report"
]

URL_ONLY_FEATURES = [
    "having_IP_Address",
    "URL_Length",
    "Shortining_Service",
    "having_At_Symbol",
    "double_slash_redirecting",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "HTTPS_token"
]


WEBPAGE_FEATURES = [
    "Favicon",
    "Request_URL",
    "URL_of_Anchor",
    "Links_in_tags",
    "SFH",
    "Submitting_to_email",
    "Abnormal_URL",
    "Redirect",
    "on_mouseover",
    "RightClick",
    "popUpWindow",
    "Iframe"
]


DOMAIN_FEATURES = [
    "SSLfinal_State",
    "Domain_registration_length",
    "port",
    "age_of_domain",
    "DNSRecord",
    "web_traffic",
    "Page_Rank",
    "Google_Index",
    "Links_pointing_to_page",
    "Statistical_report"
]

all_grouped_features = (
    URL_ONLY_FEATURES
    + WEBPAGE_FEATURES
    + DOMAIN_FEATURES
)

print("Total grouped features:", len(all_grouped_features))

missing_features = set(UCI_FEATURES) - set(all_grouped_features)

print("Missing features:", missing_features)

from webpage_analysis import (
    fetch_webpage,
    parse_webpage,
    has_favicon,
    request_url_feature,
    url_of_anchor_feature,
    links_in_tags_feature,
    sfh_feature,
    submitting_to_email_feature,
    abnormal_url_feature,
    on_mouseover_feature,
    right_click_feature,
    popup_window_feature,
    iframe_feature
)

from domain_analysis import (
    dns_record_feature,
    port_feature,
    domain_registration_length,
    age_of_domain
)

def extract_all_features(url):
    """
    Extract all currently supported features
    from a URL, webpage HTML, and domain information.
    """

    features = {}

    # URL features
    features.update(extract_basic_features(url))

    # Domain features
    features["Domain_registration_length"] = (
        domain_registration_length(url)
    )

    features["port"] = port_feature(url)

    features["age_of_domain"] = age_of_domain(url)

    features["DNSRecord"] = dns_record_feature(url)

    # Webpage features
    html, final_url = fetch_webpage(url)

    soup = parse_webpage(html)

    features["Favicon"] = has_favicon(soup)

    features["Request_URL"] = request_url_feature(
        soup,
        final_url
    )

    features["URL_of_Anchor"] = url_of_anchor_feature(
        soup,
        final_url
    )

    features["Links_in_tags"] = links_in_tags_feature(
        soup,
        final_url
    )

    features["SFH"] = sfh_feature(
        soup,
        final_url
    )

    features["Submitting_to_email"] = (
        submitting_to_email_feature(soup)
    )

    features["Abnormal_URL"] = abnormal_url_feature(
        soup,
        final_url
    )

    features["on_mouseover"] = on_mouseover_feature(soup)

    features["RightClick"] = right_click_feature(soup)

    features["popUpWindow"] = popup_window_feature(soup)

    features["Iframe"] = iframe_feature(soup)

    return features
