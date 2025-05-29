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
