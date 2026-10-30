# Encrypted File Transfer

A TCP file transfer system with a **C++ client** and a **Python server**, featuring hybrid encryption, a custom binary protocol, checksum verification, and persistent storage with SQLite.

Developed independently as part of the Defensive Systems Programming course at **The Open University of Israel**.

## Features

- **Hybrid encryption:** RSA-OAEP for exchanging an AES-256 key; AES-CBC for file encryption.
- **Custom binary protocol:** registration, key exchange, returning-client login, file transfer, and verification messages.
- **Chunked transfers:** encrypted file data is split into chunks of up to 1,024 bytes.
- **Checksum verification and retries:** the client compares its checksum with the server's result and retries failed verification, with up to four transfer attempts.
- **Concurrent connections:** the Python server handles connections using a thread per client.
- **Persistent state:** SQLite stores client identities, key material, last-seen timestamps, and file metadata.
- **Controlled file storage:** files are stored in per-client directories using SHA-256-derived filenames, with resolved-path checks.
- **Connection timeout:** inactive client connections time out after five minutes.

## Transfer Flow

1. The client reads the server address, client name, and file list from `transfer.json`.
2. A new client registers and sends its RSA public key. A returning client uses its saved identity.
3. The server generates an AES key and returns it encrypted with the client's RSA public key.
4. The client encrypts each file and sends the encrypted data in numbered chunks.
5. The server reassembles and decrypts the file, then returns its checksum.
6. After the client confirms a matching checksum, the server writes the file to disk and marks it as verified in SQLite.

## Technology Stack

| Component | Technologies |
| --- | --- |
| Client | C++, Windows Winsock, Crypto++ |
| Server | Python, sockets, threading, PyCryptodome |
| Database | SQLite, Python `sqlite3` |
| Cryptography | RSA-OAEP, AES-256-CBC |
| Transfer verification | CRC checksum |

## Repository Structure

```text
client/       C++ client, protocol, encryption, and configuration handling
server/       Python server, protocol, encryption, and database handling
README.md     Project overview and setup instructions
.gitignore    Exclusions for build output and local runtime data
```

## Getting Started

### Server

Requires **Python 3.10 or later**.

From the repository root:

```powershell
python -m pip install pycryptodome
cd server
python Main.py
```

To set the listening port, create `port.info` beside `Server.py`, containing a single port number:

```text
1369
```

If the file is missing or invalid, the server uses port **1369**. The client configuration must use the same port.

The server creates `defensive.db` and `files_received/` in its working directory. Start it from the same directory on subsequent runs to reuse its stored state.

### Client

The current client targets **Windows** and requires a C++17-capable compiler and **Crypto++**.

To build with Visual Studio:

1. Create a C++ console application and add the source and header files from `client/`.
2. Select C++17 or later.
3. Configure the Crypto++ include and library paths, and link its library along with `Ws2_32.lib`.
4. Ensure the Crypto++ build matches the application's architecture and runtime configuration.
5. Build the executable.

### Client Configuration

Create `transfer.json` **beside the client executable**:

```json
{
  "server": {
    "ip": "127.0.0.1",
    "port": "1369",
    "client": "demo-client"
  },
  "files": [
    "C:/transfer-demo/sample.txt"
  ]
}
```

Replace the example path with an existing file. Forward slashes avoid the need to escape Windows backslashes. Start the server, then run the client executable.

The client creates `me.info` and `priv.key` beside its executable for subsequent connections. Keep these files private and out of version control.

## File Storage

Verified files are saved under:

```text
files_received/<client-id>/<sha256-of-original-filename>
```

The original filename, storage path, and verification status are recorded in SQLite. The SHA-256 value is used to derive the storage name; transfer verification uses a separate CRC checksum.

## Scope and Limitations

This is an educational implementation of a course-defined protocol. It demonstrates network programming, cross-language protocol interoperability, encryption integration, and persistent state management.

The protocol uses 1,024-bit RSA keys and a fixed zero IV for AES-CBC. CRC detects transfer errors but does not provide cryptographic authentication. Files are buffered in memory, and the server stores AES keys in SQLite. These choices would need to be revisited before using the system for production transfers.