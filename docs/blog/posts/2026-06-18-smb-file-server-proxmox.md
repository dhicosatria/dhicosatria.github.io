---
title: SMB File Server on Proxmox
description: Centralized storage blueprint using Samba on existing Proxmox hardware.
author: Dhico Satria
date: 2026-06-18T20:21:00+07:00
tags:
  - homelab
  - storage
  - samba
  - proxmox
  - smb
---

# SMB File Server on Proxmox: Centralized Storage Blueprint

## Overview

This article documents a practical way to build a centralized SMB file server on an existing Proxmox host. No extra VM is required.

Use cases:

- VM backup repository
- Knowledge repository
- Malware sample repository
- Security data lake
- General shared storage

## Environment

### Hardware

```text
SSD #1 (372GB): Proxmox OS + VM Storage
SSD #2 (238GB): Additional VM Storage
HDD 2TB: backups, malware, datalake, share, knowledge
```

## Network

```text
OPNsense
  ├── Proxmox 192.168.1.10
  └── Client VMs
```

## Installation

```bash
apt update
apt install samba -y
```

## User and Permissions

```bash
useradd -m storageadmin
passwd storageadmin
groupadd labstorage
usermod -aG labstorage storageadmin
smbpasswd -a storageadmin
chgrp -R labstorage /mnt/storage
chmod -R 2775 /mnt/storage
```

## Samba Config

```ini
[LabStorage]
path = /mnt/storage
browseable = yes
writable = yes
guest ok = no
valid users = storageadmin
force group = labstorage
create mask = 0664
directory mask = 2775
inherit permissions = yes
```

```bash
systemctl restart smbd
testparm
```

## Access

### Linux

```bash
smbclient //192.168.1.10/LabStorage -U storageadmin
mount -t cifs //192.168.1.10/LabStorage /mnt/labstorage -o username=storageadmin
```

### Windows

\\192.168.1.10\LabStorage

## Notes

- Disable guest access
- Keep Samba updated
- Restrict to internal networks
- Do not expose SMB to internet

*Status: practice draft*
*Last updated: 2026-06-18*
