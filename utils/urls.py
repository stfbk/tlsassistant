import re
from tldextract import extract
from utils.logger import Logger


# todo: fix info logging

# logging.getLogger('tldextract').disabled = False if logging.getLogger().isEnabledFor(logging.DEBUG) else True


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
    output = f"{results.subdomain + '.' if keep_subdomain and results.subdomain != '' else ''}{results.domain}.{results.suffix}"
    Logger("URL_Domain").debug(f"parsed {url} into {output}")
    return output
