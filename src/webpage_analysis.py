import ipaddress
import socket

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

from urllib.parse import urlparse, urljoin


def is_safe_public_host(url):
    """
    Check whether the URL points to a public host.

    This prevents the analyzer from requesting localhost,
    private network addresses, or other non-public hosts.
    """

    try:
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return False

        hostname = parsed.hostname

        if not hostname:
            return False

        # Direct IP address
        try:
            ip = ipaddress.ip_address(hostname)

            return (
                not ip.is_private
                and not ip.is_loopback
                and not ip.is_link_local
                and not ip.is_reserved
                and not ip.is_multicast
            )

        except ValueError:
            pass

        # Resolve domain and check returned IP addresses
        addresses = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM
        )

        for address in addresses:
            ip = ipaddress.ip_address(address[4][0])

            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
            ):
                return False

        return True

    except Exception:
        return False


def fetch_webpage(url):
    """
    Fetch webpage HTML without following redirects.

    JavaScript is not executed.
    """

    if not is_safe_public_host(url):
        raise ValueError("URL does not point to a public host.")

    response = requests.get(
        url,
        timeout=8,
        allow_redirects=False,
        headers={
            "User-Agent": "PhishGuard/1.0"
        }
    )

    response.raise_for_status()

    return response.text, response.url


def parse_webpage(html):
    """
    Parse downloaded HTML using BeautifulSoup.
    """

    return BeautifulSoup(html, "html.parser")

def has_favicon(soup):
    """
    Check whether the webpage contains a favicon link.
    """

    favicon_links = soup.find_all(
        "link",
        href=True
    )

    for link in favicon_links:
        rel = link.get("rel", [])

        if isinstance(rel, list):
            rel = [str(item).lower() for item in rel]
        else:
            rel = [str(rel).lower()]

        if "icon" in rel or "shortcut icon" in rel:
            return 1

    return -1

def request_url_feature(soup, page_url):
    """
    Estimate the proportion of page resources
    loaded from external domains.
    """

    page_domain = urlparse(page_url).netloc

    resources = []

    # Images
    for tag in soup.find_all("img", src=True):
        resources.append(tag["src"])

    # Scripts
    for tag in soup.find_all("script", src=True):
        resources.append(tag["src"])

    # Stylesheets
    for tag in soup.find_all("link", href=True):
        resources.append(tag["href"])

    if not resources:
        return 1

    external_count = 0

    for resource in resources:
        resource_url = urljoin(page_url, resource)

        resource_domain = urlparse(resource_url).netloc

        if resource_domain and resource_domain != page_domain:
            external_count += 1

    ratio = external_count / len(resources)

    if ratio < 0.22:
        return 1
    elif ratio <= 0.61:
        return 0
    else:
        return -1


def url_of_anchor_feature(soup, page_url):
    """
    Analyze anchor links on the webpage.
    """

    page_domain = urlparse(page_url).netloc

    anchors = soup.find_all("a", href=True)

    if not anchors:
        return 1

    external_count = 0

    for anchor in anchors:
        href = anchor["href"]

        if href.startswith("#"):
            continue

        absolute_url = urljoin(page_url, href)
        domain = urlparse(absolute_url).netloc

        if domain and domain != page_domain:
            external_count += 1

    ratio = external_count / len(anchors)

    if ratio < 0.31:
        return 1
    elif ratio <= 0.67:
        return 0
    else:
        return -1

def links_in_tags_feature(soup, page_url):
    """
    Analyze links found in HTML tags.
    """

    page_domain = urlparse(page_url).netloc

    links = []

    for tag in soup.find_all(["meta", "script", "link"]):

        value = (
            tag.get("href")
            or tag.get("src")
            or tag.get("content")
        )

        if value:
            links.append(value)

    if not links:
        return 1

    external_count = 0

    for link in links:
        absolute_url = urljoin(page_url, link)

        domain = urlparse(absolute_url).netloc

        if domain and domain != page_domain:
            external_count += 1

    ratio = external_count / len(links)

    if ratio < 0.17:
        return 1
    elif ratio <= 0.81:
        return 0
    else:
        return -1

def sfh_feature(soup, page_url):
    """
    Analyze HTML form submission targets.
    """

    page_domain = urlparse(page_url).netloc

    forms = soup.find_all("form")

    if not forms:
        return 1

    suspicious_forms = 0

    for form in forms:

        action = form.get("action", "").strip()

        if action == "":
            suspicious_forms += 1
            continue

        action_url = urljoin(page_url, action)

        action_domain = urlparse(action_url).netloc

        if action_domain and action_domain != page_domain:
            suspicious_forms += 1

    ratio = suspicious_forms / len(forms)

    if ratio == 0:
        return 1
    elif ratio < 0.5:
        return 0
    else:
        return -1

def submitting_to_email_feature(soup):
    """
    Check whether a form submits data directly to an email address.
    """

    forms = soup.find_all("form")

    for form in forms:
        action = form.get("action", "").lower()

        if "mailto:" in action:
            return -1

    return 1


def abnormal_url_feature(soup, page_url):
    """
    Check whether forms or links contain suspicious
    external domains.
    """

    page_domain = urlparse(page_url).netloc

    forms = soup.find_all("form")

    for form in forms:
        action = form.get("action", "").strip()

        if action:
            action_url = urljoin(page_url, action)
            action_domain = urlparse(action_url).netloc

            if action_domain and action_domain != page_domain:
                return -1

    return 1

def redirect_feature(response_history):
    """
    Analyze HTTP redirect behavior.
    """

    if len(response_history) == 0:
        return 1
    elif len(response_history) <= 2:
        return 0
    else:
        return -1

def on_mouseover_feature(soup):
    """
    Detect JavaScript mouseover events.
    """

    elements = soup.find_all(
        attrs={"onmouseover": True}
    )

    return -1 if elements else 1

def right_click_feature(soup):
    """
    Detect JavaScript that attempts to disable right-click.
    """

    page_text = str(soup).lower()

    suspicious_patterns = [
        "contextmenu",
        "event.button==2",
        "event.button == 2",
        "return false"
    ]

    for pattern in suspicious_patterns:
        if pattern in page_text:
            return -1

    return 1

def popup_window_feature(soup):
    """
    Detect JavaScript popup functions.
    """

    scripts = soup.find_all("script")

    for script in scripts:

        script_text = script.get_text(
            strip=True
        ).lower()

        if "window.open(" in script_text:
            return -1

    return 1

def iframe_feature(soup):
    """
    Detect iframe usage.
    """

    iframes = soup.find_all("iframe")

    return -1 if iframes else 1


