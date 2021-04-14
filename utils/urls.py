import re
from tldextract import extract


def url_strip(input_url, strip_www=False):
    url = (
        re.compile(r"https?://") if not strip_www else re.compile(r"https?://(www\.)?")
    )
    return url.sub("", input_url).strip().strip("/")


def url_tld(url) -> str:
    results = extract(url)
    return f"{results.domain}.{results.suffix}"
