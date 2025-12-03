#!/bin/bash
# Usage: sudo bash install.sh [install_path]
# If no install_path is given, defaults to /opt/omgpermissions

# 1. Determine installation directory
INSTALL_DIR=${1:-/opt/omgpermissions}
echo "Installing omgpermissions to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

# 2. Copy project files to the install directory
# (Assume script is run from the root of the omgpermissions repository)
cp -r . "$INSTALL_DIR"
chmod -R 755 "$INSTALL_DIR"

# 3. Set up Python virtual environment
python3 -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"

# 4. Install required Python packages
pip install --upgrade pip
pip install msal fastapi uvicorn python-dotenv requests Jinja2 starlette litellm

# 5. (Optional) Prompt to run .env configuration script
echo "Launching configuration for environment variables..."
bash "$INSTALL_DIR/setup_env.sh"   # (This calls the .env setup script described later)

# 6. Schedule the cron job for hourly runs
# (This will add a new cron entry for the current user)
CRON_CMD="cd $INSTALL_DIR && $INSTALL_DIR/venv/bin/python -m detection_app.src.main >> $INSTALL_DIR/detection.log 2>&1"
# Check if entry already exists to avoid duplication
( crontab -l 2>/dev/null | grep -F "$INSTALL_DIR/venv/bin/python -m detection_app.src.main" ) || \
  ( crontab -l 2>/dev/null; echo "0 * * * * $CRON_CMD" ) | crontab -
echo "Cron job installed to run detection hourly."
