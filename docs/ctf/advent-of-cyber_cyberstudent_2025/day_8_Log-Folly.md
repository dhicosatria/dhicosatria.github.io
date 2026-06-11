# day 7 Log Folly

category : cryptography

## **Description**

A quiet morning never lasts long at North Pole Security. Your console lights up with a new message from Jingle McSnark. He writes:

> “Since you somehow solved my last challenge I made something actually secure this time. True discrete log strength. Unbreakable. And I even rotate the secret every round so you cannot rely on patterns. This is real cryptography human.”
> 

The attachment is a small script and a long list of leaks. Snowdrift walks by, sees the file, and whispers

> “He still keeps exponentiating the wrong thing”
> 

You open the file. It takes about three seconds to realize Jingle has once again misunderstood what makes discrete log hard. Recover the hidden message before he starts bragging to the whole SOC.

## **Attachments**

[**chall.py](https://files.vipin.xyz/api/public/dl/uWwjYBJO/advent-of-ctf-csd/2025/Day%208/chall.py)[out.txt](https://files.vipin.xyz/api/public/dl/f0Yvwsbl/advent-of-ctf-csd/2025/Day%208/out.txt)**

[**chall.py**](https://files.vipin.xyz/api/public/dl/uWwjYBJO/advent-of-ctf-csd/2025/Day%208/chall.py)

[**out.txt**](https://files.vipin.xyz/api/public/dl/f0Yvwsbl/advent-of-ctf-csd/2025/Day%208/out.txt)

clue:

Two leaks combined the right way is better than one.
****Look for **arithmetic relations** between rotated flags.
****

## 1. Challenge Overview

We are given a script that:

- Generates a 256-bit prime `p` and uses generator `g = 2`
- Converts the current FLAG string to integer `x = bytes_to_long(FLAG)`
- Prints `leak = 2^x mod p`
- Rotates the FLAG by 1 byte per round

The output file contains every cyclic rotation of the flag encoded as exponentiations of 2.

Despite claims of “true discrete log strength,” this design is cryptographically broken because the exponential structure leaks *linear relationships* between rotations.

## 2. How the FLAG Is Processed

Let the flag bytes be:

[b0, b1, b2, …, b(n−1)]

Round 0:

- x0 = bytes_to_long([b0, b1, …, b(n−1)])
- leak0 = 2^x0 mod p

Round 1:

- FLAG rotated left → [b1, b2, …, b(n−1), b0]
- x1 = bytes_to_long(rotated FLAG)
- leak1 = 2^x1 mod p

Continuing this process gives a sequence of leaks representing all cyclic rotations.

This introduces exploitable algebraic relationships.

## 3. Relationship Between Rotated Exponents

Definition:

x0 = b0·256^(n−1) + b1·256^(n−2) + … + b(n−1)

x1 = b1·256^(n−1) + b2·256^(n−2) + … + b0

Compute:

x1 − 256 · x0 = b0 · (1 − 256^n)

This is an *exact integer identity*.

Reduce modulo (p − 1) because exponents in modulo p arithmetic work mod (p − 1):

Let:

- e0 = x0 mod (p−1)
- e1 = x1 mod (p−1)
- K = (1 − 256^n) mod (p−1)

Then:

e1 − 256·e0 ≡ K·b0 (mod p−1)

Now convert back into group values:

h0 = 2^e0 mod p

h1 = 2^e1 mod p

Compute:

t0 = h1 · h0^(−256) mod p

t0 = 2^(K·b0) mod p

This depends on only:

- the constant K
- the unknown byte b0
- the small brute-force space 0–255

Thus, recovering a byte requires checking at most 256 possibilities, **not** solving a discrete log.

## 4. Generalizing to All Bytes

For each rotation i:

t(i) = leak(i+1) · leak(i)^(−256) mod p

t(i) = 2^(K·b(i)) mod p

Wrapping around for the last byte:

leak(n) = leak(0)

So each of the n bytes is recovered individually by checking all b ∈ [0, 255]:

Find b such that:

2^(K b) mod p = t(i)

This is trivial and fast.

## 5. Complete Solver (Python)

Paste this into a script:

```python
from Crypto.Util.number import inverse

with open("out.txt") as f:
lines = [l.strip() for l in f.readlines()]

p = int(lines[0].split()[1])
leaks = [int(l.split()[1]) for l in lines[1:]]

n = len(leaks)
pm1 = p - 1

K = (1 - pow(256, n, pm1)) % pm1

lookup = { }
for b in range(256):
lookup[pow(2, (K * b) % pm1, p)] = b

flag_bytes = []
for i in range(n):
h_i = leaks[i]
h_j = leaks[(i + 1) %n]

inv = pow(h_i, pm1 - 1, p)
t = (h_j * pow(inv, 256, p)) % p

flag_bytes.append(lookup[t])

flag = bytes(flag_bytes).decode()
print(flag)

```

## 6. Final Results

Recovered FLAG:

csd{n0t_s0_unbr34k4bl3_bc3e9f1c}