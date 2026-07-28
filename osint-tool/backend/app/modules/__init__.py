"""
Importing this package automatically registers all modules
(each one uses the @register decorator on import).

To add a new module: create it in this folder and import it here.
"""

# `hibp` and `shodan` are optional, key-based modules: they register like any
# other plugin and skip themselves automatically when their key is unset.
from . import (
    crtsh_module,  # noqa: F401
    dns_module,  # noqa: F401
    email_module,  # noqa: F401
    github_module,  # noqa: F401
    hibp_module,  # noqa: F401
    http_module,  # noqa: F401
    ip_module,  # noqa: F401
    phone_module,  # noqa: F401
    rdap_module,  # noqa: F401
    robots_module,  # noqa: F401
    shodan_module,  # noqa: F401
    tls_module,  # noqa: F401
    username_module,  # noqa: F401
    wayback_module,  # noqa: F401
    whois_module,  # noqa: F401
)
