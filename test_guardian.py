import subprocess
import os

message = 'Test "message" with quotes'
title = 'Test "title"'

script = 'display notification (system attribute "AEGIS_MSG") with title (system attribute "AEGIS_TITLE") sound name "Basso"'

env = os.environ.copy()
env["AEGIS_MSG"] = message
env["AEGIS_TITLE"] = title

subprocess.run(["osascript", "-e", script], env=env, check=False, timeout=3)
