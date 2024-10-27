
# Mr Crypter

Mr Crypter is a command-line tool built using Python's `Typer` framework to provide encryption and decryption functionalities. 
With Mr Crypter, users can securely encrypt and decrypt files using a password-based approach, as well as manage encrypted files conveniently.

## Features
- **File Encryption**: Encrypt files with a password for added security.
- **File Decryption**: Decrypt encrypted files with the same password.
- **Read Encrypted Files**: Temporarily decrypt and view file content without altering the original file.
- **Change Password**: Update the encryption password securely.
- **List Encrypted Files**: Display a list of all files encrypted by Mr Crypter.

## Installation

1. Clone the repository or copy the `mr_crypter.py` file to your project directory.
2. Install the required dependencies by running:

    ```bash
    pip install typer cryptography
    ```

3. Make sure to have `Python 3.7` or above installed.

## Usage

### Initial Setup
When using Mr Crypter for the first time, you will be prompted to set a password. This password will be used for encryption and decryption.

### Commands
Below are the commands available with Mr Crypter:

#### Encrypt a File
Encrypt a specified file and log its details.

```bash
python main.py encrypt FILE_PATH
```

#### Decrypt a File
Decrypt a previously encrypted file.

```bash
python main.py decrypt FILE_PATH
```
#### or
```bash
python main.py decrypt SHORTCUT
```


#### Temporarily Read Encrypted File
Read and display the content of an encrypted file without modifying it.

```bash
python main.py view FILE_PATH
```


#### Temporarily Opens Encrypted File & Inserts Text
```bash
python main.py insert FILE_PATH "New content to add"
```

#### Change Password
Change the current password after authenticating with the old password.

```bash
python main.py change-password
```

#### List Encrypted Files
Display all files encrypted using Mr Crypter.

```bash
python main.py list-encrypted-files
```

#### Clears The Log Of Encrypted Files & Shortcut

```bash
python main.py clear-log
```

## Configuration Files

Mr Crypter uses the following configuration files and directories to manage encryption:

- **Configuration Directory**: `~/.file_encryptor/`
- **Salt File**: `salt.key` - Stores the salt used for hashing.
- **Config Hash**: `config.hash` - Stores the password hash.
- **Encrypted Files Log**: `encrypted_files.csv` - Logs all encrypted files.

## Security Notes
- Your password is hashed and stored securely; however, remember that if you forget the password, encrypted files cannot be decrypted.
- The salt and password hash are stored locally in the configuration directory.
- Use a strong password to enhance security.

## Example

Encrypt a file:

```bash
python main.py encrypt ~/Documents/sample.txt
```

Decrypt the same file:

```bash
python mr_crypter.py decrypt ~/Documents/sample.txt
```

## License
This project is licensed under the MIT License - see the LICENSE file for details.
