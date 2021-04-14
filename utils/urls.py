import re
from tldextract import extract
import logging


def url_strip(input_url, strip_www=False):
    url = (
        re.compile(r"https?://") if not strip_www else re.compile(r"https?://(www\.)?")
    )
    return url.sub("", input_url).strip().strip("/")


def url_domain(url, keep_subdomain=True) -> str:
    results = extract(url)
    output = f"{results.subdomain + '.' if keep_subdomain and results.subdomain != '' else ''}{results.domain}.{results.suffix}"
    logging.debug(f"[url_domain] parsed {url} into {output}")
    return output
