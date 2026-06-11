# Automated LFI to NTLMv2 Lab

## Overview
This lab simulates a real-world attack chain where a **Local File Inclusion (LFI) vulnerability**
is abused to **trigger outbound SMB authentication**, allowing an attacker to capture
**NTLMv2 hashes**.

The environment is designed for **offensive security practice**, focusing on:  Web exploitation, Windows authentication abuse, Credential interception.

## Repository
🔗 GitHub:
https://github.com/dhicosatria/automated-lfi-to-ntlmv2-lab

## Attack Flow
1. Identify LFI vulnerability in the web application
2. Use LFI to access a UNC path (`\\\\attacker\\share`)
3. Victim server initiates SMB authentication
4. Capture NTLMv2 hash using Responder
5. (Optional) Crack hash offline

## Tools Used
- Docker / Docker Compose
- Apache / PHP
- Responder
- Impacket
- Hashcat

## Learning Objectives
- Understand NTLM authentication flow
- Abuse LFI beyond file reading
- Capture and analyze NTLMv2 hashes
- Simulate realistic internal attack scenarios

## Disclaimer
This lab is intended **for educational and authorized testing purposes only**.
