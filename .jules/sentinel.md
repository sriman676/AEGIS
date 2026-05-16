## 2025-02-14 - AppleScript Command Injection in aegis_guardian.py
**Vulnerability:** The `display notification` AppleScript string in `_notify` used f-strings to inject user-controlled input (`message` and `title`) into the script, opening a vector for arbitrary command execution when invoking `osascript`.
**Learning:** Shell-interpreted commands like AppleScript (`osascript`) inherently evaluate inputs; string interpolation bypasses the protections typically provided by passing an array to `subprocess.run()`.
**Prevention:** Pass external/user-controlled inputs safely using environment variables (`os.environ`) and retrieve them securely within the shell-interpreted script (e.g., using `system attribute "VAR_NAME"` in AppleScript).
