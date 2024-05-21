# passman
passman is a password manager that stores passwords locally in an encrypted database file, using PBKDF2 with AES256-GCM encryption.

## Installation (Windows)
To install passman on windows, just download the passman.exe file from the [Releases](https://github.com/removingnest109/passman/releases) page.

The program is a standalone .exe and can be placed anywhere on the system without issues.

## Installation (Linux)
Executables can be found on the [Releases](https://github.com/removingnest109/passman/releases) page.

To install the executable binary on linux, download and extract the passman-x86_64-linux-bin.tar.gz.

This archive contains a binary file that can be placed anywhere in the system, but it is best to place it somewhere that is included in your $PATH.

Alternatively, if you have Cargo installed, you can also build passman from source:

```bash
git clone https://github.com/removingnest109/passman.git

cd passman

cargo install --path .
```

If you build the program using "cargo install" on linux, it will place the executable in ~/.cargo/bin/

## Usage
When you open passman, it will prompt you to login with a master password. This master password is used to derive new, randomly salted encryption keys for each entry into your password database. 

For security reasons your master password is never stored on disk, only in memory after you have entered it to login. This also means that since the master password is only actually used to derive the encryption keys, the master password is not applied to the database until an entry is added.

### For example:

You login to passman for the first time with your master password as "password123", but you do not add any password entries to the database. When you close passman and open it back up, it will still allow you to use any password to login to the empty database.

However, if the database has any data in it, it can only be opened with the correct master password. This means if you lose the master password, you will also lose the data on the database. If you are in a scenario where you have lost the password and need to create a new master password, the database must be deleted from the data directory - for Windows this is %APPDATA%/passman, and for linux this is typically ~/.local/share/passman. The new empty database is generated the next time passman is launched.
