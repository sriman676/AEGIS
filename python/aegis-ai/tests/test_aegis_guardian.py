import unittest
from unittest.mock import patch, MagicMock
import os
import sys

# Ensure python/aegis-ai is in path to import aegis_guardian
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import aegis_guardian

class TestAegisGuardian(unittest.TestCase):
    @patch("aegis_guardian.platform.system")
    @patch("aegis_guardian.subprocess.run")
    def test_notify_darwin_secure_osascript(self, mock_run, mock_platform):
        """
        Verify that _notify on Darwin (macOS) uses secure system attributes
        to pass the title and message, preventing osascript command injection.
        """
        mock_platform.return_value = "Darwin"

        test_title = 'Hack "Title"'
        test_message = 'Hack "Message"'

        aegis_guardian._notify(test_title, test_message)

        mock_run.assert_called_once()
        args, kwargs = mock_run.call_args

        # Check that the script relies on `system attribute`
        script_args = args[0]
        self.assertEqual(script_args[0], "osascript")
        self.assertEqual(script_args[1], "-e")
        self.assertIn('system attribute "AEGIS_MSG"', script_args[2])
        self.assertIn('system attribute "AEGIS_TITLE"', script_args[2])
        self.assertNotIn(test_title, script_args[2])
        self.assertNotIn(test_message, script_args[2])

        # Check that env variables correctly hold the potentially malicious payloads
        self.assertIn("env", kwargs)
        self.assertEqual(kwargs["env"]["AEGIS_MSG"], test_message)
        self.assertEqual(kwargs["env"]["AEGIS_TITLE"], test_title)

if __name__ == "__main__":
    unittest.main()
