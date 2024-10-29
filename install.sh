#!/bin/bash

# Check for Python 3.7+ and pip
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is not installed. Please install it and try again."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(sys.version_info[:2] >= (3, 7))')
if [ "$PYTHON_VERSION" != "True" ]; then
    echo "Python 3.7 or higher is required. Please update Python and try again."
    exit 1
fi

if ! command -v pip &> /dev/null; then
    echo "pip is not installed. Please install it and try again."
    exit 1
fi

# Check for --uninstall option
if [ "$1" == "--uninstall" ]; then
    echo "Uninstalling mr-crypter..."
    sudo rm -f /usr/local/bin/mr-crypter
    rm -rf .venv
    rm -rf ~/.file_encryptor
    echo "mr-crypter has been uninstalled."
    exit 0
fi

# Check if mr-crypter is already installed
if [ -f "/usr/local/bin/mr-crypter" ]; then
    read -p "mr-crypter is already installed. Do you want to overwrite it? (y/n): " choice
    case "$choice" in 
      y|Y ) echo "Overwriting existing mr-crypter...";;
      n|N ) echo "Installation aborted."; exit 1;;
      * ) echo "Invalid choice. Installation aborted."; exit 1;;
    esac
fi

# Define the virtual environment directory
VENV_DIR=".venv"

# Create a virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating a virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

# Activate the virtual environment
source "$VENV_DIR/bin/activate"

# Install required Python packages in the virtual environment
echo "Installing required Python packages..."
pip install -r requirements.txt

# Add shebang line if not present
if ! grep -q "^#!/usr/bin/env python3" main.py; then
    echo "Adding shebang line to main.py..."
    sed -i '1i #!/usr/bin/env python3' main.py
fi

# Modify main.py to use the virtual environment's Python interpreter directly
VENV_PYTHON_PATH="#!$(pwd)/$VENV_DIR/bin/python3"
sed -i "1s|^.*$|$VENV_PYTHON_PATH|" main.py

# Make the script executable
echo "Making main.py executable..."
chmod +x main.py

# Rename the script
echo "Renaming main.py to mr-crypter..."
mv main.py mr-crypter

# Move the script to /usr/local/bin
echo "Moving mr-crypter to /usr/local/bin..."
sudo mv mr-crypter /usr/local/bin/

# Deactivate the virtual environment
deactivate

echo "Installation complete. You can now use 'mr-crypter' from anywhere."
echo "Virtual environment created at $(pwd)/$VENV_DIR"
