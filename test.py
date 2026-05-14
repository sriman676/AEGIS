import subprocess
message = "hello"
title = "world"
script = """
on run argv
  display notification (item 1 of argv) with title (item 2 of argv) sound name "Basso"
end run
"""
subprocess.run(["osascript", "-e", script, message, title])
