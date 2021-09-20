from modules.server.wrappers.certificate import Certificate

def enumerate(hostname:str, force = False)->list:
    """
    Enumerate subdomains of a given hostname.
    :param hostname: The hostname to enumerate subdomains for.
    :return: A list of subdomains.
    """
    subdomains = []
    cert = Certificate().run(hostname = hostname, force = force)
    return [k for k in cert.keys() if hostname in k ]
    