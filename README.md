# ModernSSH — Reimagining SSH with Modern Cryptography

A secure, modular remote shell tool built as a graduation project.  
ModernSSH replaces the traditional SSH protocol with modern, layered cryptographic primitives to provide encrypted communication, credential protection, and command execution — all over a TLS-encrypted channel.

---

## Project Goals

 “How can we reimagine SSH using modern TLS and modular security layers?”

- Use standardized, well-audited cryptographic components instead of a monolithic protocol.
- Demonstrate secure remote shell design with clear separation of concerns.
- Explore authentication, encryption, replay protection, and secure key exchange in Python.

---

## Features

- **TLS 1.2+** for secure transport and server/client certificate validation.
- **RSA-OAEP** to bootstrap a fresh AES session key and encrypt user credentials.
- **AES-EAX (AEAD)** for fast, authenticated encryption of commands and outputs.
- **Replay Protection** using timestamps and nonces.
- **bcrypt** for securely storing and verifying user passwords.
- Role-based command filtering (admin vs. normal user).

---

## Architecture

Client <====== TLS (X.509) ======> Server
  │                                  │
  ├── RSA-OAEP: Encrypts login info  │
  │                                  ├── Decrypts & validates credentials
  ├── AES-EAX: Encrypts commands     ├── Executes or rejects commands
  ├── Reads AES-EAX encrypted reply  └── Sends authenticated output
  
  # POC :
  ![test1](https://github.com/user-attachments/assets/5b1d1807-97c2-47a9-96be-e7d086fbb144)
![test4](https://github.com/user-attachments/assets/65467d10-1b89-4bba-a7d0-fb0d12473040)
![test3](https://github.com/user-attachments/assets/2781cd69-76cd-43e2-846b-29824a472590)
![test2](https://github.com/user-attachments/assets/58fc314c-36b6-4b2f-88de-6d40e0753841)
