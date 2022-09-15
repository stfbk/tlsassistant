from enum import Enum

class WebserverType(Enum):
    """
    Enum for configuration file types
    """

    AUTO = 0
    APACHE = 1
    NGINX = 2

class PortType: # No inheritance from Enum
    """
    Type of configuration.
    """

    NONE = 0
    HTTP = 80
    SSL = 443
