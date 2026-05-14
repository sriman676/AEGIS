import sys
import os
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'python/aegis-ai')))
import aegis_guardian

@patch('platform.system', return_value='Darwin')
@patch('subprocess.run')
def test_mac_notify(mock_run, mock_platform):
    aegis_guardian._notify("Secure Title", 'Secure "Message"')

    mock_run.assert_called_once()
    args, kwargs = mock_run.call_args
    assert args[0] == ["osascript", "-e", 'display notification (system attribute "AEGIS_MSG") with title (system attribute "AEGIS_TITLE") sound name "Basso"']
    assert "env" in kwargs
    assert kwargs["env"]["AEGIS_MSG"] == 'Secure "Message"'
    assert kwargs["env"]["AEGIS_TITLE"] == "Secure Title"
    print("Test passed!")

test_mac_notify()
