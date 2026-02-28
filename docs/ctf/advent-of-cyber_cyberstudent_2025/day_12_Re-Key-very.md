# day 12 Re-Key-very

category : cryptography

## **Description**

The Krampus Syndicate proudly claims their new signing service uses "bitcoin-level encryption" and industry-standard elliptic-curve cryptography. According to their engineers, the system is mathematically sound, battle-tested, and designed so that there is absolutely no way to recover the signing key, even if you can see every signature it produces.

To prove their point, they've released a small transcript of signed messages. No private material and no access to the signer - just a few legitimate signatures generated with all the best practices of 2025.

Your task is to audit that claim. You can assume the cryptography itself is correct, and the curve is secure. Brute force, as always, won't help you here. The weakness, if any, lies not in the math that's there, but in how it might be used. Carefully model the signing process and determine whether the Syndicate's confidence is actually justified.

If they're right, the key is unrecoverable, and the holidays may turn dark once again.

If they're wrong, however, you'll prove that even their "bitcoin-level encryption" can fall apart under the smallest implementation oversight.

Of course, knowing the operative you are, you can easily surmount this. Recover the hidden secret.

## **Attachments**


[**gen.py**](https://files.vipin.xyz/api/public/dl/UjvOjfLN/Day%2012/gen.py)

[**out.txt**](https://files.vipin.xyz/api/public/dl/_iohJsnd/Day%2012/out.txt)

solver

```jsx
import hashlib

# secp256k1 order
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def inv(a, m=n):
    return pow(a, m-2, m)

def H(m: bytes) -> int:
    return int.from_bytes(hashlib.sha256(m).digest(), "big")

msgs = [
    b"Beware the Krampus Syndicate!",
    b"Santa is watching...",
    b"Good luck getting the key"
]

r0 = int("a4312e31e6803220d694d1040391e8b7cc25a9b2592245fb586ce90a2b010b63", 16)
s0 = int("e54321716f79543591ab4c67e989af3af301e62b3b70354b04e429d57f85aa2e", 16)
r1 = int("6c5f7047d21df064b3294de7d117dd1f7ccf5af872d053f12bddd4c6eb9f6192", 16)
s1 = int("1ccf403d4a520bc3822c300516da8b29be93423ab544fb8dbff24ca0e1368367", 16)
r2 = int("2c15aceb49e63e4a2c8357102fbd345ac2cbd1b214c77fba0cd9ffe8d20d2c1e", 16)
s2 = int("1ee49ef3857ad1d9ff3109bfb4a91cb464ab6fdc88ace610ead7e6dee0957d95", 16)

z0, z1, z2 = map(H, msgs)

Delta = (s0*r1 - r0*s1) % n
d = ((z0*s1 + s0*(s1 - z1)) % n) * inv(Delta) % n
k = ((r0*(s1 - z1) + r1*z0) % n) * inv(Delta) % n

# sanity check with 3rd signature (nonce should be k+2)
assert (z2 + r2*d) % n == (s2 * ((k+2) % n)) % n

# gen.py does: d = (int(key) % (n-1)) + 1  => key_int = d-1 (for usual case)
key_int = (d - 1) % (n - 1)
flag = key_int.to_bytes((key_int.bit_length()+7)//8, "big")
print(flag.decode())

```

flag :

**`csd{pr3d1ct4bl3_n0nc3_==_w34k}`**