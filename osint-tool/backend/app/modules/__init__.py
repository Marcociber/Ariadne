"""
Importing this package automatically registers all modules
(each one uses the @register decorator on import).

To add a new module: create it in this folder and import it here.
"""
from . import dns_module        # noqa: F401
from . import whois_module      # noqa: F401
from . import crtsh_module      # noqa: F401
from . import email_module      # noqa: F401
from . import username_module   # noqa: F401
from . import phone_module      # noqa: F401
# Optional, key-based modules (skipped automatically when their key is unset).
from . import shodan_module     # noqa: F401
from . import hibp_module       # noqa: F401
