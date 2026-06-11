# day 10 Jingle's Validator

## **Description**

The North Pole Licensing Division needed offline activation for internal tools. Jingle McSnark volunteered to build the validator.

Three weeks later, he emailed the entire department. Called it "military-grade." Refused code review. Attached the binary and said it was uncrackable.

Snowdrift replied-all: "Let me know when you want a second opinion."

Jingle hasn't responded. Attached is an internal test build. Prove him wrong... again.

## **Attachments**

[**jollyvm**](https://files.vipin.xyz/api/public/dl/Pbruom3x/day10/jollyvm)

[**jollyvm**](https://files.vipin.xyz/api/public/dl/Pbruom3x/day10/jollyvm)

hint :

- You may have noticed the program is emulating some instructions, like a virtual machine. Some of these instructions may be specialized for the program.
- Once you've figured out the instructions, analyze the higher level program. How much of the state actually changes before your input is encrypted?
****

## Initial Reconnaissance

### File Inspection

```bash
file jollyvm

```

Output:

```
ELF64-bit LSB executable, x86-64, dynamically linked

```

### Execution Test

```bash
./jollyvm

```

Output:

```
Enter licensekey:

```

Random input:

```
Invalid license.

```

The program performs **local input validation** without network interaction.

---

## Input Length Check

Static analysis in **Ghidra** reveals:

```c
read(0, buf,0x34);

```

License key length:

```
0x34hex =52bytes

```

Any input not exactly 52 characters fails.

---

## Virtual Machine Discovery

While analyzing `main()`, we observe:

- No direct string comparison
- Heavy use of registers
- Large byte array in `.rodata`
- Instruction dispatch logic

 The program implements a **custom virtual machine (VM)**.

This matches the challenge hint:

> “The program is emulating some instructions, like a virtual machine.”
> 

---

## VM High-Level Logic

The VM:

1. Takes user input (52 bytes)
2. Splits it into **13 blocks of 4 bytes**
3. Encrypts each block
4. Compares result with a constant table in `.rodata`

If all blocks match → license valid.

---

## Encryption Algorithm

### Helper Function `g(x)`

```c
g(x) = ((x >>3) ^ (x >>5) ^ (x >>8) ^ (x >>12)) &0xff

```

- XOR-based
- Produces **1 byte**
- Cryptographically weak

---

### Encryption Process Per Block

Initial state:

```c
state =0xf337;

```

For each plaintext block `P[i]`:

```
T = (state <<8) | g(state)
C = P[i] XOR T
state = (T <<8) | g(P[i])

```

Where:

- `P[i]` = plaintext block
- `C` = ciphertext block
- `T` = keystream

**State depends on plaintext** , major design flaw.

---

## Critical Weakness: Seed from Last Block

Before encryption begins, the state is **seeded using the last plaintext block**:

```c
state = g(P[12]);

```

However:

- `g()` only depends on **20 lower bits**
- Entropy = `2^20 = 1,048,576`

 **Bruteforce feasible**

---

## Attack Strategy

We know:

```
C[i]=Encrypt(P[i])

```

Goal:

```
FindPsuchthatEncrypt(P)==KnownCiphertext

```

### Steps:

1. Extract ciphertext table from `.rodata`
2. Bruteforce all `2^20` seed values
3. Decrypt ciphertext using guessed seed
4. Validate:
    - Last block seed matches
    - All characters printable ASCII

---

## Solver Script

```python
defg(x):
return ((x>>3) ^ (x>>5) ^ (x>>8) ^ (x>>12)) &0xff

```

Bruteforce logic:

```python
for seedinrange(2**20):
    plaintext = decrypt(seed)
if is_printable(plaintext):
print(plaintext)
break

```

---

Recovered license key:

```
csd{I5_4ny7HiN9_R34LlY_R4Nd0m_1F_it5_bru73F0rc4B1e?}

```

Verification:

```bash
./jollyvm
Enter license key:
csd{I5_4ny7HiN9_R34LlY_R4Nd0m_1F_it5_bru73F0rc4B1e?}

```