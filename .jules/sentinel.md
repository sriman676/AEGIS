## 2024-05-15 - [Command Injection in AppleScript Notifications]
**Vulnerability:** Command injection in `aegis_guardian.py` via unescaped string interpolation in AppleScript `display notification` command.
**Learning:** Even desktop notifications can lead to Remote Code Execution (RCE) if user-controlled input (like threat reasoning from a websocket event) is directly interpolated into shell-interpreted tools like `osascript`.
**Prevention:** Always pass user-controlled inputs via environment variables (e.g., `system attribute "VAR"`) instead of string formatting when using `osascript`.
