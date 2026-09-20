import socket
from datetime import datetime

import whois
from urllib.parse import urlparse


def get_hostname(url):
    """
    Extract hostname from URL.
    """

    return urlparse(url).hostname


def dns_record_feature(url):
    """
    Check whether the domain has a DNS record.
    """

    hostname = get_hostname(url)

    if not hostname:
        return -1

    try:
        socket.gethostbyname(hostname)
        return 1

    except socket.gaierror:
        return -1


def port_feature(url):
    """
    Check whether the URL uses a standard HTTP/HTTPS port.
    """

    parsed = urlparse(url)

    port = parsed.port

    if port is None:
        return 1

    if port in (80, 443):
        return 1

    return -1


def domain_registration_length(url):
    """
    Estimate domain registration duration using WHOIS data.
    """

    hostname = get_hostname(url)

    if not hostname:
        return -1

    try:
        data = whois.whois(hostname)

        creation_date = data.creation_date
        expiration_date = data.expiration_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        if not creation_date or not expiration_date:
            return 0

        duration = expiration_date - creation_date

        days = duration.days

        if days > 365:
            return 1
        else:
            return -1

    except Exception:
        return 0


def age_of_domain(url):
    """
    Estimate whether the domain is older than one year.
    """

    hostname = get_hostname(url)

    if not hostname:
        return -1

    try:
        data = whois.whois(hostname)

        creation_date = data.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return 0

        age_days = (
            datetime.utcnow() - creation_date
        ).days

        if age_days > 365:
            return 1
        else:
            return -1

    except Exception:
        return 0


