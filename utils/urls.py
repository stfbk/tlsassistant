import re
from tldextract import extract
from utils.logger import Logger
import ipaddress


def port_parse(port: str) -> str:
    """
    Parse port, checks for validity.

    :param port: The port number.
    :type port: str
    :return: stripped port.
    :rtype: str
    :raise AssertionError: If invalid number of port.
    """
    assert 1 <= int(port) <= 65535, "The port number is invalid!"
    return str(int(port))  # truncate floating point if any


def link_sep(input_url: str) -> [str, str]:
    """
    Strip URL with and obtain url and port.

    :param input_url: The url to strip
    :type input_url: str
    :return: stripped url and the port.
    :rtype: list of str
    """
    splitted = url_strip(input_url).rsplit(":", 1)
    if len(splitted) != 2:
        splitted.append("443")
    splitted[1] = splitted[1].split("/", 1)[0].split("?", 1)[0]
    splitted[1] = port_parse(splitted[1])
    return splitted


def url_strip(input_url, strip_www=False) -> str:
    """
    Strip URL with regex and obtain domain (DEPRECATED, USE url_domain).

    deprecated:: 2.0.alpha
    Use :func:`url_domain` instead.

    :param input_url: The url to strip
    :type input_url: str
    :param strip_www: Strip also the www
    :type strip_www: bool
    :return: stripped url.
    :rtype: str
    """

    url = (
        re.compile(r"https?://") if not strip_www else re.compile(r"https?://(www\.)?")
    )
    return url.sub("", input_url).strip().strip("/")


def url_domain(url, keep_subdomain=True) -> str:
    """
    Strip URL and obtain domain.

    :param url: The url to strip
    :type url: str
    :param keep_subdomain: keep the subdomain, default True
    :type keep_subdomain: bool
    :return: stripped url.
    :rtype: str
    """
    results = extract(url)
    output = (
        f"{results.subdomain + '.' if keep_subdomain and results.subdomain != '' else ''}{results.domain}"
        f"{'.' + results.suffix if results.suffix != '' else ''}"
    )
    Logger("URL_Domain").debug(f"parsed {url} into {output}")
    return output


def has_wildcard(url) -> bool:
    """
    Check if the url contains a wildcard in last subdomain.

    :param url: The url to check
    :type url: str
    :return: True if the url contains a wildcard in the last subdomain, False otherwise
    :rtype: bool
    """
    subdomain = extract(url).subdomain
    return subdomain.split(".")[0] == "*"  # check if last subdomain is a wildcard


def remove_wildcard(url) -> str:
    """
    Remove the wildcard from the last subdomain.

    :param url: The url to remove the wildcard from
    :type url: str
    :return: The url without the wildcard
    :rtype: str
    """
    return url_domain(url)[2:]


def validate_ip(ip: str) -> bool:
    """
    Validate an IP
    :param ip: String to check if it's an IP.
    :type ip: str
    :return: True if ip param it's an IP, false otherwise.
    :rtype: bool
    """
    try:
        _ = ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def cache_name(hostname: str, port: str=443):
    """
    Create a cache name for the hostname and port.

    :param hostname: The hostname
    :type hostname: str
    :param port: The port
    :type port: str
    :return: The cache name
    :rtype: str
    """
    return f"{hostname}_{port}" if port != "" else hostname