![Project Logo](./logo_.png)

Mr Crypter is a command-line tool built using Python's `Typer` framework to provide encryption and decryption functionalities. 
With Mr Crypter, users can securely encrypt and decrypt files using a password-based approach, as well as manage encrypted files conveniently.

## Features
- **File Encryption**: Encrypt files with a password for added security.
- **File Decryption**: Decrypt encrypted files with the same password.
- **Read Encrypted Files**: Temporarily decrypt and view file content without altering the original file.
- **Change Password**: Update the encryption password securely.
- **List Encrypted Files**: Display a list of all files encrypted by Mr Crypter.
- **Search Encrypted Files**: Search through encrypted files by filename or shortcut.
- **Built-in Help**: Comprehensive help system with detailed command information.

## Installation: PIP

1. Clone the repository or copy the `main.py` file to your project directory.
2. Install the required dependencies by running:

    ```bash
    pip install -r requirements.txt
    ```

3. Make sure to have `Python 3.7` or above installed.

## Installation: Unix & Windows

### For unix based systems
Use the `install.sh` script if you want easy installation. And make it available from anywhere.
```bash
./install.sh
```
### For windows based systems
Use the `install.py` script if you want easy installation. And make it available from anywhere.
```bash
python install.py
```
After installation, you can use `mr-crypter` [COMMAND] from anywhere.


## Usage

### Initial Setup
When using Mr Crypter for the first time, you will need to set a password. This password will be used for encryption and decryption, use the `change-password` command to set the password.

### Getting Help
Mr Crypter includes a comprehensive help system. You can access it in two ways:

```bash
# Show all available commands and general help
mr-crypter help

# Get detailed help for a specific command
mr-crypter help COMMAND
```

For example:
```bash
mr-crypter help encrypt
```

### Commands
Below are the commands available with Mr Crypter:

----------------------------------------------------------
#### Encrypt a File
Encrypt a specified file and log its details.

```bash
mr-crypter encrypt FILE_PATH
```
----------------------------------------------------------
#### Decrypt a File
Decrypt a previously encrypted file.

```bash
mr-crypter decrypt FILE_PATH
```
#### or
```bash
mr-crypter decrypt SHORTCUT
```

----------------------------------------------------------
#### Temporarily Read Encrypted File
Read and display the content of an encrypted file without modifying it.

```bash
mr-crypter view FILE_PATH [--lines NUMBER]
```
#### or
```bash
mr-crypter view SHORTCUT [--lines NUMBER]
```

Options:
- `--lines`, `-n`: Number of lines to display (optional)

Examples:
```bash
# View entire file
mr-crypter view document.txt

# View first 10 lines only
mr-crypter view document.txt --lines 10

# View first 5 lines using shortcut
mr-crypter view doc_shortcut -n 5
```

----------------------------------------------------------
#### Temporarily Opens Encrypted File & Inserts Text
```bash
mr-crypter insert FILE_PATH "New content to add"
```
#### or
```bash
mr-crypter insert SHORTCUT "New content to add"
```

----------------------------------------------------------
#### List Encrypted Files
Display all files encrypted using Mr Crypter.

```bash
mr-crypter list-files
```

----------------------------------------------------------
#### Clears The Log Of Encrypted Files & Shortcut

```bash
mr-crypter clear-log
```

----------------------------------------------------------
#### Search Encrypted Files
Search through encrypted files by filename or shortcut.

```bash
mr-crypter search SEARCH_TERM
```

Options:
- `--shortcuts/--no-shortcuts`: Include or exclude shortcuts in search (default: include)
- `--case-sensitive`: Make search case-sensitive (default: case-insensitive)

Examples:
```bash
# Basic search
mr-crypter search document

# Case-sensitive search
mr-crypter search PDF --case-sensitive

# Search only in filenames (exclude shortcuts)
mr-crypter search report --no-shortcuts
```

## Configuration Files

Mr Crypter uses the following configuration files and directories to manage encryption:

- **Configuration Directory**: `~/.file_encryptor/`
- **Salt File**: `salt.key` - Stores the salt used for key derivation
- **Encrypted Files Log**: `encrypted_files.csv` - Logs all encrypted files
- **Log File**: `file_encryptor.log` - Stores error logs


## Security Notes
- Your password is never stored; only a salt for key derivation is kept
- Each file has its own verification tag for integrity checking
- Keys are derived on-demand and immediately cleared from memory
- Use a strong password to enhance security

## Example

Encrypt a file:

```bash
mr-crypter encrypt ~/Documents/sample.txt
```

Decrypt the same file:

```bash
mr-crypter decrypt ~/Documents/sample.txt
```

Get help on encryption:

```bash
mr-crypter help encrypt
```

## License
This project is licensed under the MIT License - see the LICENSE file for details.
