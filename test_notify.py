import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'python/aegis-ai')))
from aegis_guardian import _notify

_notify("Hello", 'Test "message"')
