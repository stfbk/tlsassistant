import sys
import os
import logging

from utils.paths import tlsa_data_dir

logging.basicConfig(level=logging.WARNING)

_BASE = str(tlsa_data_dir())
sys.path.append(os.path.join(_BASE, "dependencies"))
_sebastian_path = os.path.join(_BASE, "dependencies/SEBASTiAn/src")
if os.path.isdir(_sebastian_path):
    sys.path.append(_sebastian_path)
sys.path.append(os.path.join(_BASE, "dependencies/tls-compliance-dataset/utils"))
