# LoFAD - Log File Anomaly Detector
# Package initialization file

# Package metadata
__version__ = "1.0.0"
__author__ = "LoFAD Team"
__license__ = "MIT"

# Import main public API from internal modules
from .detector import LoFAD
from .alerts import send_email, send_slack, abuseipdb_check
from .patterns import AUTH_PATTERNS, CMD_PATTERNS
from .utils import RotatingTail

# Define what is exposed when `from lofad import *` is used
__all__ = [
    "LoFAD",
    "send_email",
    "send_slack",
    "abuseipdb_check",
    "AUTH_PATTERNS",
    "CMD_PATTERNS",
    "RotatingTail",
]

