import unittest
from unittest.mock import patch, MagicMock
import os
import platform

# Pre-import `os` in sys.modules, wait, `aegis_guardian.py` doesn't import os.
# We'll fix `aegis_guardian.py` and test the notification function.
