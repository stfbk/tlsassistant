import sys
import os
import logging

logging.basicConfig(level=logging.WARNING)
sys.path.append(os.path.abspath("dependencies"))
sys.path.append(os.path.abspath("dependencies/SEBASTiAn/src"))
sys.path.append(os.path.abspath("dependencies/tls-compliance-dataset/utils"))