# Functional Enhancements

## These are possible things I might add in the future, nothing is set in stone though

### Auto-Complete for Shortcuts
- **Description**: Allow users to press a key to auto-complete a shortcut based on stored shortcuts, speeding up workflows and minimizing typing errors.
- **Implementation**: Utilize libraries like `prompt_toolkit` with `typer` to enable autocomplete for shortcuts.

### Add better Support for PDF
- **Description**: Add support for PDF files, allowing users to encrypt and decrypt PDF files, as well as view them.
- **Implementation**: Use libraries like `PyMuPDF` to handle PDF files.

~~### Encryption Status and Metadata~~
~~- **Description**: Store additional metadata like the date of encryption, file size, and encryption status.~~
~~- **Output**: Display this metadata in the `list-files` output, helping users quickly understand each file’s status.~~ ✅

~~### Searchable List of Encrypted Files~~
~~- **Description**: Add a search command to filter encrypted files by name or shortcut, making it easy to locate specific files.~~ ✅

### Configurable Encryption Settings
- **Description**: Allow users to specify encryption strength (e.g., AES-128, AES-256) and customize chunk size for file reading during encryption.
- **Implementation**: Provide a `settings` command to easily adjust these configurations.

### Backup and Restore Encrypted File List
- **Description**: Enable users to back up the `encrypted_files.csv` log and restore it later, helpful in case of accidental deletion or for migration to a new machine.

### Encryption History
- **Description**: Keep a record of encryption and decryption events with timestamps, allowing users to track access history for each file.

~~### Batch Encryption/Decryption~~
~~- **Description**: Support batch processing by enabling users to encrypt or decrypt multiple files simultaneously by specifying a directory.~~
~~- **Implementation**: Introduce `batch-encrypt` and `batch-decrypt` commands to process all files in a specified folder.~~✅

# UI/UX Improvements

~~### Enhanced Loading Bar with Rich Progress~~
~~- **Description**: Provide more detailed feedback during encryption/decryption, showing elapsed time, estimated remaining time, and progress percentage.~~
~~- **Implementation**: Use `Rich`’s `Progress` component for a more granular loading experience.~~ ✅

### Detailed Error Messages with Suggestions
- **Description**: Instead of generic error messages like "File not found" or "Incorrect password," provide context and suggestions (e.g., “Did you mean to use the `list-files` command?”).
- **Implementation**: Achieve this with `typer`’s exception handling.

~~### File Preview Option with Line Limit~~
~~- **Description**: When viewing an encrypted file, display only the first few lines by default and allow users to specify how many lines they want to view (e.g., `--lines 10`).~~
~~- **Benefit**: Helps avoid overloading the terminal when viewing large files.~~ ✅

~~### Color-Coded File Status~~
~~- **Description**: Use color codes to visually distinguish encrypted (e.g., red) and decrypted (e.g., green) files in lists for easy identification.~~ ✅

### Interactive Menu for Commands
- **Description**: Implement an interactive menu system to guide users through different commands without needing to type each one manually.
- **Implementation**: Use libraries like `InquirerPy` to create a user-friendly menu experience.

### Shortcuts for Recent Files
- **Description**: Keep a log of recently used files, allowing users to re-encrypt, decrypt, or view them with a single command.
- **Implementation**: Maintain a “recently used” list accessible via shortcuts like `recent` or `last`.

# Security and Convenience Features

### Session-Based Authentication
- **Description**: After logging in with the password, create a temporary session that keeps the user authenticated for a short period (e.g., 15 minutes), reducing the need to re-enter the password for each command.
- **Implementation**: Use a temporary token or flag stored in a secure file that expires after a set time or upon program exit.

### Password Recovery Option
- **Description**: Add an option for password recovery. Generate recovery codes upon setup and save them securely for user retrieval if they forget the main password.

### Key Management
- **Description**: Allow users to generate new encryption keys on demand for different files, making it possible to compartmentalize encryption by key, which is useful for highly sensitive data.
