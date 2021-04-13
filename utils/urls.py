import re


def url_strip(input_url,strip_www=False):
    url = re.compile(r"https?://") if not strip_www else re.compile(r"https?://(www\.)?")
    return url.sub('', input_url).strip().strip('/')
