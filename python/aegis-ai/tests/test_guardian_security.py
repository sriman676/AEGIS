import os
import platform
import subprocess
from unittest.mock import patch, MagicMock
import sys

# Add the directory containing aegis_guardian.py to sys.path
sys.path.append('python/aegis-ai')

from aegis_guardian import _notify

def test_notify_linux():
    print("Testing Linux notification...")
    with patch('platform.system', return_value='Linux'):
        with patch('subprocess.run') as mock_run:
            _notify("Title", "Message")
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert "notify-send" in args
            assert "Title" in args
            assert "Message" in args
            print("Linux notification test passed.")

def test_notify_darwin_secure():
    print("Testing macOS (Darwin) secure notification...")
    with patch('platform.system', return_value='Darwin'):
        with patch('subprocess.run') as mock_run:
            _notify("Title' with injection; echo vulnerable", "Message' with injection; echo vulnerable")
            mock_run.assert_called_once()
            args, kwargs = mock_run.call_args
            env = kwargs.get('env')
            assert env['NOTIFY_TITLE'] == "Title' with injection; echo vulnerable"
            assert env['NOTIFY_MSG'] == "Message' with injection; echo vulnerable"
            script = args[0][2]
            assert 'system attribute "NOTIFY_TITLE"' in script
            assert 'system attribute "NOTIFY_MSG"' in script
            # Ensure the vulnerable variables are NOT in the script string itself
            assert "Title' with injection" not in script
            print("macOS secure notification test passed.")

def test_notify_windows_secure():
    print("Testing Windows secure notification...")
    with patch('platform.system', return_value='Windows'):
        with patch('subprocess.run') as mock_run:
            _notify("Title' ; whoami", "Message' ; whoami")
            mock_run.assert_called_once()
            args, kwargs = mock_run.call_args
            env = kwargs.get('env')
            assert env['NOTIFY_TITLE'] == "Title' ; whoami"
            assert env['NOTIFY_MSG'] == "Message' ; whoami"
            powershell_cmd = args[0][2]
            assert "$env:NOTIFY_TITLE" in powershell_cmd
            assert "$env:NOTIFY_MSG" in powershell_cmd
            # Ensure the vulnerable variables are NOT in the command string itself
            assert "whoami" not in powershell_cmd
            print("Windows secure notification test passed.")

if __name__ == "__main__":
    try:
        test_notify_linux()
        test_notify_darwin_secure()
        test_notify_windows_secure()
        print("\nAll notification security tests passed!")
    except Exception as e:
        print(f"\nTest failed: {e}")
        exit(1)
