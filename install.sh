#!/bin/bash
set -e

echo "=========================================="
echo "    Installing AEGIS Security Platform   "
echo "=========================================="

echo "[+] Verifying dependencies..."
if ! command -v docker &> /dev/null; then
    echo "[-] Docker is required but not installed. Please install Docker first."
    exit 1
fi

echo "[+] Pulling the latest AEGIS docker images..."
docker-compose pull || echo "No pre-built images found, will build from source."

echo "[+] Building AEGIS containers..."
docker-compose build

echo "[+] Starting AEGIS securely..."
docker-compose up -d

echo "[+] Installing Python dependencies for AEGIS Guardian..."
PYTHON_VENV="python/aegis-ai/.venv/bin/python"
if [ -f "$PYTHON_VENV" ]; then
    $PYTHON_VENV -m pip install websockets --quiet
    # macOS: pync for notifications; Linux: notify-send is usually pre-installed
    if [[ "$OSTYPE" == "darwin"* ]]; then
        $PYTHON_VENV -m pip install pync --quiet
    fi
    echo "[+] AEGIS Guardian dependencies installed."
else
    echo "[!] Virtual env not found. Run: cd python/aegis-ai && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
    PYTHON_VENV="python3"
fi

echo "[+] Starting AEGIS Guardian as background daemon..."
GUARDIAN_PATH="$(pwd)/python/aegis-ai/aegis_guardian.py"

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Register systemd user service
    SYSTEMD_DIR="$HOME/.config/systemd/user"
    mkdir -p "$SYSTEMD_DIR"
    cat > "$SYSTEMD_DIR/aegis-guardian.service" << EOF
[Unit]
Description=AEGIS Guardian — Background Security Monitor
After=network.target

[Service]
ExecStart=$PYTHON_VENV $GUARDIAN_PATH
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF
    systemctl --user daemon-reload
    systemctl --user enable aegis-guardian.service
    systemctl --user start aegis-guardian.service
    echo "[+] AEGIS Guardian registered as systemd user service."

elif [[ "$OSTYPE" == "darwin"* ]]; then
    # Register LaunchAgent for macOS
    PLIST_PATH="$HOME/Library/LaunchAgents/com.aegis.guardian.plist"
    cat > "$PLIST_PATH" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.aegis.guardian</string>
    <key>ProgramArguments</key>
    <array>
        <string>$PYTHON_VENV</string>
        <string>$GUARDIAN_PATH</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/aegis-guardian.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/aegis-guardian-error.log</string>
</dict>
</plist>
EOF
    launchctl load "$PLIST_PATH"
    echo "[+] AEGIS Guardian registered as macOS LaunchAgent."

else
    # Generic background start
    nohup $PYTHON_VENV "$GUARDIAN_PATH" > /tmp/aegis-guardian.log 2>&1 &
    echo "[+] AEGIS Guardian started (PID $!)."
fi

echo "=========================================="
echo " AEGIS is now running."
echo " Dashboard: http://localhost:5173"
echo " API:       http://localhost:8000"
echo " Guardian:  Running in background (notifications active)"
echo "=========================================="
