import sys
from unittest.mock import MagicMock

# Prevent importing modules with hardware or system dependencies during test collection
sys.modules.setdefault('RPi', MagicMock())
sys.modules.setdefault('RPi.GPIO', MagicMock())
sys.modules.setdefault('pyzbar', MagicMock())
sys.modules.setdefault('pyzbar.pyzbar', MagicMock())
sys.modules.setdefault('pysatochip', MagicMock())
sys.modules.setdefault('pysatochip.JCconstants', MagicMock())
sys.modules.setdefault('pysatochip.util', MagicMock())
sys.modules.setdefault('pysatochip.CardConnector', MagicMock())
