# cursed – File Encryption & Search Tool

A low-level encryption utility built in C as part of UNSW's COMP1521 course.  
It features permission-aware XOR encryption, ECB-style shift encryption, and recursive file searching by name or binary content.

---

## 🔧 Features

- ✅ Print and change the current working directory
- ✅ List directory contents with file permissions
- ✅ Check if a file is encryptable based on file system permissions
- ✅ XOR encrypt/decrypt binary files
- ✅ ECB-mode shift encryption/decryption with a password block
- ✅ Recursively search directories by:
  - Filename
  - Byte-pattern content
- ❌ (CBC mode included but not implemented — left as extension)

---

## 🧠 Key Concepts

- File I/O and bitwise operations
- Linux file permissions
- Directory traversal using `dirent.h` and `stat`
- XOR-based encryption
- ECB-mode byte-shifting encryption
- Dynamic memory and error handling

---

## 🚀 How to Build & Run

### 1. Compile
```bash
gcc -o cursed cursed.c

# 🔍 Print the current working directory
./cursed                # triggers print_current_directory()

# 📁 Change to a new directory (e.g. Documents)
./cursed cd Documents

# 📂 List all files in the current directory with permissions
./cursed ls

# 🔐 XOR encrypt a file
./cursed xor file.txt file_encrypted.txt

# 🔓 XOR decrypt back to original
./cursed xor file_encrypted.txt file_decrypted.txt

# 🔐 ECB-mode encrypt with 8-byte password
./cursed ecb-encrypt file.txt "password"

# 🔓 ECB-mode decrypt
./cursed ecb-decrypt file.txt.ecb "password"

# 🔎 Search by filename (recursively)
./cursed search-name log

# 🔍 Search by binary content (e.g. hex pattern "deadbeef")
./cursed search-content deadbeef

# 🧪 Check if a file is encryptable (permissions + type)
./cursed check file.txt
