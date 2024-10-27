#!/bin/bash

# Install required Python packages
echo "Installing required Python packages..."
pip install -r requirements.txt

# Add shebang line if not present
if ! grep -q "^#!/usr/bin/env python3" main.py; then
    echo "Adding shebang line to main.py..."
    sed -i '1i #!/usr/bin/env python3' main.py
fi

# Make the script executable
echo "Making main.py executable..."
chmod +x main.py

# Rename the script
echo "Renaming main.py to mr-crypter..."
mv main.py mr-crypter

# Move the script to /usr/local/bin
echo "Moving mr-crypter to /usr/local/bin..."
sudo mv mr-crypter /usr/local/bin/

echo "Installation complete. You can now use 'mr-crypter' from anywhere."
