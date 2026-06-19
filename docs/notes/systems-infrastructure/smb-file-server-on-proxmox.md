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

This article documents a practical way to build a centralized SMB file server on an existing Proxmox host. The goal is to reuse available storage for lab files, backups, and shared working directories without adding another VM.

The design is intentionally simple. It is suitable for an internal homelab or security lab, but it still needs hardening because SMB is a common lateral-movement target.

## Use Cases

This setup can be useful for:

- VM backup repository
- Knowledge repository
- Malware sample repository
- Security data lake
- General shared storage

For sensitive or destructive files, especially malware samples, use a separate directory and stricter access rules. Do not expose the same share broadly to all lab machines.

## Scope and Threat Model

This is an internal file server pattern for a trusted network segment. It is not designed as a public file-sharing service.

Primary risks:

- Credential theft from a compromised client
- Ransomware encrypting writable shares
- Accidental deletion from Windows or Linux clients
- Lateral movement through overly broad SMB access
- Data loss from relying on one local disk

Baseline rules:

- Do not expose SMB to the internet.
- Restrict SMB to trusted internal subnets.
- Use named users and groups, not guest access.
- Keep writable access narrow.
- Keep a separate backup path outside the SMB share.

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

Only trusted clients should reach TCP 445 on the Proxmox host. If possible, keep management traffic, storage access, and lab machines on separate VLANs or firewall zones.

## Disk Layout and Mounting

Assume the 2TB HDD is mounted at `/mnt/storage`.

Suggested directory layout:

```text
/mnt/storage
├── backups
├── datalake
├── knowledge
├── malware
└── share
```

Validate the disk before exposing it through Samba:

```bash
lsblk
df -h
mount | grep /mnt/storage
```

For a simple single-disk setup, ext4 is usually enough. If the storage is backed by ZFS, use snapshots for recovery and keep Samba pointed at a dataset that is intentionally created for sharing.

## Installation

```bash
apt update
apt install samba -y
```

## User and Permission Model

Create a dedicated Unix user and group for the share:

```bash
useradd -m storageadmin
passwd storageadmin
groupadd labstorage
usermod -aG labstorage storageadmin
smbpasswd -a storageadmin
```

Create the directory structure and assign group ownership:

```bash
mkdir -p /mnt/storage/{backups,datalake,knowledge,malware,share}
chgrp -R labstorage /mnt/storage
chmod -R 2770 /mnt/storage
find /mnt/storage -type d -exec chmod g+s {} \;
```

The setgid bit keeps new files and directories under the `labstorage` group. Samba permissions still depend on Linux filesystem permissions, so fix both sides when troubleshooting access issues.

For a malware repository, consider a separate group such as `malwarelab` and make most users read-only. Writable malware storage should be limited to accounts that actually need it.

## Samba Configuration

Edit `/etc/samba/smb.conf` and keep the global configuration strict:

```ini
[global]
server role = standalone server
workgroup = WORKGROUP
map to guest = never
server min protocol = SMB3
smb encrypt = desired
server signing = mandatory
hosts allow = 192.168.1.0/24 127.
hosts deny = 0.0.0.0/0
log file = /var/log/samba/log.%m
max log size = 1000
```

Then define the lab storage share:

```ini
[LabStorage]
path = /mnt/storage
browseable = yes
writable = yes
guest ok = no
valid users = @labstorage
force group = labstorage
create mask = 0660
directory mask = 2770
inherit permissions = yes
```

`smb encrypt = desired` allows encryption when the client supports it. For stricter environments, use `required`, but expect a performance cost.

Validate and restart:

```bash
testparm
systemctl restart smbd
systemctl status smbd
```

## Firewall and Network Restriction

At the firewall level, allow SMB only from trusted internal clients.

Minimum ports:

```text
TCP 445: SMB over TCP
```

Avoid opening legacy NetBIOS ports unless there is a specific need:

```text
TCP 139
UDP 137
UDP 138
```

If OPNsense controls the network, create a rule that allows TCP 445 only from the client VLAN or trusted lab subnet to the Proxmox storage IP.

## Access from Clients

### Linux

```bash
smbclient //192.168.1.10/LabStorage -U storageadmin
mount -t cifs //192.168.1.10/LabStorage /mnt/labstorage -o username=storageadmin
```

For a persistent client mount, use a credentials file instead of putting the password directly in `/etc/fstab`:

```bash
cat /etc/samba/labstorage.cred
```

```ini
username=storageadmin
password=change-this-password
```

```bash
chmod 600 /etc/samba/labstorage.cred
```

Example mount option:

```text
//192.168.1.10/LabStorage /mnt/labstorage cifs credentials=/etc/samba/labstorage.cred,vers=3.1.1,iocharset=utf8 0 0
```

### Windows

Open File Explorer and use:

```text
\\192.168.1.10\LabStorage
```

Map it as a network drive only on machines that should retain access. Avoid saving credentials on disposable or frequently compromised lab VMs.

## Backup and Recovery

An SMB share is not a backup if the only copy lives on the same disk.

Minimum recovery plan:

- Keep VM backups in a separate backup target when possible.
- Use ZFS snapshots if the storage lives on a ZFS dataset.
- Keep an external or offsite copy for important data.
- Test restore periodically, not only backup creation.
- Use a simple retention policy such as daily, weekly, and monthly copies.

For Proxmox workloads, Proxmox Backup Server is a better backup target than a plain writable SMB share. SMB can still be useful for exported artifacts, lab files, and temporary working data.

## Recycle Bin Protection

Samba can keep deleted files in a recycle directory. This helps with accidental deletion, but it is not a ransomware defense and does not replace backup.

Example share-level configuration:

```ini
vfs objects = recycle
recycle:repository = .recycle/%U
recycle:keeptree = yes
recycle:versions = yes
recycle:touch = yes
recycle:exclude = *.tmp,*.temp,~$*
recycle:exclude_dir = /tmp,/cache
```

Create and protect the recycle directory:

```bash
mkdir -p /mnt/storage/.recycle
chgrp labstorage /mnt/storage/.recycle
chmod 2770 /mnt/storage/.recycle
```

Review and clean this directory regularly because deleted files will continue consuming disk space.

## Audit Logging

For troubleshooting or investigation, Samba can log file operations with `vfs_full_audit`.

Example:

```ini
vfs objects = full_audit
full_audit:prefix = %u|%I|%m|%S
full_audit:success = mkdir rmdir rename unlink write pwrite create_file
full_audit:failure = none
full_audit:facility = local5
full_audit:priority = notice
```

If you also use the recycle module, combine both objects:

```ini
vfs objects = recycle full_audit
```

Audit logging can be noisy. Enable it intentionally, rotate logs, and watch disk usage.

## Monitoring and Maintenance

Useful commands:

```bash
systemctl status smbd
journalctl -u smbd --since today
smbstatus
testparm
df -h
du -sh /mnt/storage/*
```

Operational routine:

- Apply Debian/Proxmox security updates.
- Review active Samba users.
- Check free disk space.
- Check backup jobs and restore one sample file.
- Review Samba logs for repeated failed login attempts.
- Check disk health with SMART tooling if available.

## Validation Checklist

Server-side checks:

```bash
testparm
smbclient -L localhost -U storageadmin
systemctl status smbd
```

Linux client checks:

```bash
smbclient //192.168.1.10/LabStorage -U storageadmin
mkdir -p /mnt/labstorage
mount -t cifs //192.168.1.10/LabStorage /mnt/labstorage -o username=storageadmin,vers=3.1.1
touch /mnt/labstorage/write-test.txt
rm /mnt/labstorage/write-test.txt
```

Windows client checks:

- Open `\\192.168.1.10\LabStorage`.
- Create a test file.
- Rename the test file.
- Delete the test file.
- Confirm deleted files go to `.recycle` if recycle support is enabled.

Negative checks:

- Guest access should fail.
- Users outside `labstorage` should not write.
- Clients outside the allowed subnet should not connect.

## Production Notes

For a more production-oriented setup:

- Prefer a dedicated storage server or NAS for critical shared storage.
- Use least-privilege groups per share.
- Use read-only shares where possible.
- Separate malware, backups, and knowledge data into different shares.
- Use snapshots plus independent backup.
- Monitor disk health, capacity, and failed authentication.
- Document who owns each share and why it exists.

## When Not to Use This Setup

Avoid this pattern when you need:

- High availability
- Strong multi-tenant isolation
- Public file sharing
- Compliance-grade audit and retention
- Critical production storage with no maintenance window

In those cases, use a dedicated NAS, TrueNAS, Proxmox Backup Server, or a storage design with stronger isolation and operational controls.

## Closing Notes

Running Samba directly on a Proxmox host can be practical for a small lab, but keep the blast radius clear. Treat SMB as an internal service, restrict write access, test restores, and avoid mixing trusted storage with disposable lab machines without access control.

*Status: production-aware lab draft*
*Last updated: 2026-06-18*
