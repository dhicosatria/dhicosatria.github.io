# Guide My Drone Tonight

category : Reverse engineering

## **Description**

The North Pole has managed to get access to the **Krampus Syndicate's** internal supply drones. Perhaps if you can guide one of the drones to a nearby location we control, they can take it in for further analysis (and you'll get a flag :p).

They've hooked up the access point to this server, but you only get a short amount of time before the drone system detects something wrong and kicks you off the connection. Access the endpoint @ **`nc ctf.csd.lol 6969`**

Unfortunately, the North Pole have no idea how the drones communicate. All they've recovered is this test client taken off of an old leaked code database. It's up to you to figure out how to recover these drones.

## **Attachments**

[**client**](https://files.vipin.xyz/api/public/dl/GPKV0tV9/day17/client)

hint :

- If you send an invalid input to the server, you might be able to use the error messages to figure out what part was invalid.
- Someone with a red nose told me remote only has 1000 unique nodes...

---

The server models drones as nodes in a graph:

- Nodes have neighbors (maximum ±1000 total nodes)
- Drones move between nodes via MOVE
- Flags only appear on specific nodes

No shortcuts; you must explore the graph.

Binary analysis:

Each packet has an 8-byte header:

| Offset | Size | Description |
| --- | --- | --- |
| 0x00 | 4 | Magic `"KMPS"` |
| 0x04 | 1 | Version (1) |
| 0x05 | 1 | Message Type |
| 0x06 | 2 | Total Length (little-endian) |

---

### Message Types

From the results of decompilation and traffic observation:

| Type | Name | Fungsi |
| --- | --- | --- |
| 1 | HELLO | Handshake awal |
| 2 | STATE | Ambil posisi drone & neighbor |
| 3 | MOVE | Pindah ke node lain |
| 4 | FLAG | Cek apakah sudah di target |

solver

```jsx
#!/usr/bin/env python3
import socket, struct, time, random

HOST="ctf.csd.lol"
PORT=6969
MAGIC=b"KMPS"
VER=1

def pkt(t, payload=b""):
    length = 8 + len(payload)
    return MAGIC + bytes([VER, t]) + struct.pack("<H", length) + payload

def recv_exact(s,n):
    b=b""
    while len(b)<n:
        c=s.recv(n-len(b))
        if not c:
            raise EOFError("closed")
        b+=c
    return b

def connect():
    s=socket.create_connection((HOST,PORT),timeout=5)
    s.settimeout(5)
    s.sendall(pkt(1))
    recv_exact(s,0x10)
    return s

def get_state(s):
    s.sendall(pkt(2))
    hdr = recv_exact(s,8)
    length = struct.unpack("<H", hdr[6:8])[0]
    payload = recv_exact(s,length-8)

    token = struct.unpack("<I", payload[0:4])[0]
    n     = struct.unpack("<I", payload[4:8])[0]
    neigh = list(struct.unpack("<"+"I"*n, payload[8:8+n*4])) if n else []
    return token, neigh

def move(s, token, nxt):
    payload = struct.pack("<II", nxt, (nxt ^ token) & 0xffffffff)
    s.sendall(pkt(3, payload))
    hdr = recv_exact(s,8)
    recv_exact(s,4)  # new node id (ignored)
    return

def get_flag(s):
    s.sendall(pkt(4))
    hdr = recv_exact(s,8)
    length = struct.unpack("<H", hdr[6:8])[0]
    payload = recv_exact(s,length-8)
    if payload.startswith(b"csd{"):
        return payload.split(b"\x00")[0].decode()
    return None

def solve_once():
    s = connect()
    visited = set()

    try:
        while True:
            f = get_flag(s)
            if f:
                print("[+] FLAG:", f)
                return True

            token, neigh = get_state(s)
            random.shuffle(neigh)

            moved = False
            for nb in neigh:
                edge = (token, nb)
                if edge not in visited:
                    visited.add(edge)
                    move(s, token, nb)
                    moved = True
                    break

            if not moved:
                # dead-end → random hop (still valid neighbor)
                if neigh:
                    move(s, token, random.choice(neigh))
                else:
                    return False

    except Exception:
        return False
    finally:
        try: s.close()
        except: pass

if __name__ == "__main__":
    for i in range(30):
        print(f"[*] Attempt {i+1}")
        if solve_once():
            break
        time.sleep(0.2)
```

```jsx
┌──(kali㉿kali)-[~/Downloads/cyberstudent/17 des] 
└─$ python3 solve.py 
[*] Attempt 1 
[*] Attempt 2 
[*] Attempt 3 
[+] FLAG: csd{h00r4y_now_U_h4v3_a_dr0ne_army_5846a7b30c}
```

csd{h00r4y_now_U_h4v3_a_dr0ne_army_5846a7b30c}