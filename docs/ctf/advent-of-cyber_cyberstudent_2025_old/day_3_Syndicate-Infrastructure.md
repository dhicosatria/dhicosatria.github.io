# day 3 Syndicate Infrastructure

**Syndicate Infrastructure**

**Category :** Miscellaneous

## **Description**

Our monitoring systems have flagged suspicious DNS activity originating from a domain registered by the **KRAMPUS SYNDICATE**. Initial analysis suggests they're using it to coordinate operations against crucial North Pole systems.

The domain in question: **`krampus.csd.lol`**

We need you to perform a full DNS reconnaissance sweep. The Syndicate thinks they're clever, hiding their infrastructure in plain sight but they're wrong.

Map their infrastructure. Find what they're hiding. Report back before they realize we're onto them.

- *NPLD Threat Intelligence Division*

---

Note: All the information we need is in the DNS records. Dig deep.

## Summary

All the necessary information is hidden in the public DNS records. The domain is managed through Cloudflare (public AXFR/zone-transfer is likely blocked). By searching through NS/TXT/SPF/DMARC/SRV/DKIM, we found artifacts pointing to the exfil subdomain and eventually found a base64 string in the DKIM selector record `syndicate._domainkey.krampus.csd.lol`, which, when decoded, yields the CTF flag.

**Flag:** `csd{dn5_m19HT_B3_K1ND4_W0NKy}`

---

## Step by step

### 1. Check authoritative nameserver/SOA

```
Resolve-DnsName -Name krampus.csd.lol -Type NS

```

Result (SOA): the zone is at Cloudflare[(harmony.ns.cloudflare.com](http://harmony.ns.cloudflare.com/)) - meaning public zone transfer is almost certainly blocked.

> Implications: AXFR rarely works; we must follow the instructions in the DNS records (TXT, SPF, SRV, DKIM, etc.) according to the challenge hint.
> 

---

### 2. Check MX/SPF

```
Resolve-DnsName -Name krampus.csd.lol -Type TXT
```

**Result TXT**: `v=spf1 include:_spf.krampus.csd.lol -all`

```
Resolve-DnsName -Name _spf.krampus.csd.lol -Type TXT
```

**Result _spf**: `v=spf1 ip4:203.0.113.0/24 ~all`

- Note: `mail.krampus.csd.lol` pointing at `127.0.0.1` looks like red-herring or intentional misdirection.

---

### 3. Check DMARC

```
Resolve-DnsName -Name _dmarc.krampus.csd.lol -Type TXT
```

Result:

```
v=DMARC1; p=reject; rua=mailto:dmarc@krampus.csd.lol; ruf=mailto:forensics@ops.krampus.csd.lol; fo=1; adkim=s; aspf=s

```

- `ruf` pointing at `forensics@ops.krampus.csd.lol` suggests there is an ops subdomain worth checking out.

---

### 4`.Checkops` subdomain (hint from DMARC)

```
Resolve-DnsName -Name ops.krampus.csd.lol -Type TXT

```

**Result**:

```
internal-services:
_ldap._tcp.krampus.csd.lol
_kerberos._tcp.krampus.csd.lol
_metrics._tcp.krampus.csd.lol

```

- > `ops` contains a list of SRV services that we should query.

---

### 5. Query the listed SRV records

```
Resolve-DnsName -Name _ldap._tcp.krampus.csd.lol -Type SRV

```

**Result**: target = `dc01.krampus.csd.lol`, additional A = `203.0.113.1` (port 389)

```
Resolve-DnsName -Name _kerberos._tcp.krampus.csd.lol -Type SRV

```

**Result**: target = `dc01.krampus.csd.lol` (port 88)

```
Resolve-DnsName -Name _metrics._tcp.krampus.csd.lol -Type SRV

```

**Result**: target = `beacon.krampus.csd.lol`, additional A = `203.0.113.2` (port 443)

- Meaning: there is a host `dc01` and `beacon` on /24 203.0.113.0/24 (as per SPF include).

---

### 6. Check TXT on `beacon` and `dc01`

```
Resolve-DnsName -Name beacon.krampus.csd.lol -Type TXT

```

**Result**:

```
config=ZXhmaWwua3JhbXB1cy5jc2QubG9s==
```

- It looks like Base64. We decode it:
    - `ZXhmaWwua3JhbXB1cy5jc2QubG9s==` → **`exfil.krampus.csd.lol`**

> Interpretation: beacon stores a pointer (config) to exfil.krampus.csd.lol - indicating exfiltration target.
> 

`dc01` does not return any useful TXT (SOA/response authority seen), so focus on `exfil`.

---

### 7. Check subdomain `exfil`

```
Resolve-DnsName -Name exfil.krampus.csd.lol -Type TXT

```

**Result**:

```
status=active; auth=dkim; selector=syndicate

```

- Immediate information: exfil active, authentication via DKIM, DKIM selector named `syndicate` - means we should check `syndicate._domainkey.exfil.krampus.csd.lol` **or** possibly `syndicate._domainkey.krampus.csd.lol` (need to try both patterns).
- You tried both variants:
    - `syndicate._domainkey.exfil.krampus.csd.lol` → **nothing**
    - `syndicate._domainkey.krampus.csd`.`lol` → **exists** and returns a DKIM TXT.

---

### 8. Retrieve DKIM selector`(syndicate._domainkey.krampus.csd.lol`)

```
Resolve-DnsName -Name syndicate._domainkey.krampus.csd.lol -Type TXT

```

**Result** (Strings part `p=` very important):

```
v=DKIM1; k=rsa; p=Y3Nke2RuNV9tMTlIVF9CM1...9LMU5ENF9XME5LeX0=

```

- `p=` field in DKIM contains the public key; here `p=` contains a base64 string that appears not to be a normal RSA public-key but a **short string** that is clearly disguised as a base64 payload.

> We merge the split parts (PowerShell splits the lines). Once merged, the base64 string is:
> 

```
Y3Nke2RuNV9tMTlIVF9CM19LMU5ENF9XME5LeX0=

```

Decode base64:

```
Y3Nke2RuNV9tMTlIVF9CM19LMU5ENF9XME5LeX0=  -->  csd{dn5_m19HT_B3_K1ND4_W0NKy}

```
![Day 3 – Syndicate Infrastructure](media/day3.png)

That's **exactly the** format of the `csd{...}` flag.

---

## Analysis / Reasoning

1. **No subdomain bruteforce**: we follow the existing *records*`(_dmarc` → points to `ops` → TXT lists services → SRV → hosts → TXT config → pointers → exfil → TXT → DKIM selector,). This is a *logical path* that utilizes inter-record relationships (DMARC → ops → SRV → beacon → exfil → DKIM).
2. **Use of base64**: often CTFs hide flags in fields that usually contain base64 (e.g. TXT DKIM `p=` or TXT config). Decoding base64 is a natural step.
3. **Cloudflare**: closed AXFR, so only public records are available; challenge is intentionally designed so that participants follow the instructions in the records, not brute force.
4. **Red-herrings**: `mail.krampus.csd.lol` → `127.0.0.1` - this is clearly intended to mislead or indicate internal-only mail routing.

---

## summarized

1. `krampus.csd.lol` NS: Cloudflare → AXFR likely failed.
2. `TXT krampus.csd.lol` → SPF include `_spf.krampus.csd.lol` → shows subnet `203.0.113.0/24`.
3. `_dmarc` → `ruf=forensics@ops.krampus.csd.lol` → check `ops`.
4. `ops` TXT → SRV list: `_ldap`, `_kerberos`, `_metrics`.
5. `_metrics` SRV → target `beacon.krampus.csd.lol` → `beacon` TXT `config=ZXh...==` → base64 → `exfil.krampus.csd.lol`.
6. `exfil` TXT → `status=active; auth=dkim; selector=syndicate`.
7. `syndicate._domainkey.krampus.csd.lol` TXT → `p=Y3Nk...=` → base64 decode → `csd{dn5_m19HT_B3_K1ND4_W0NKy}`.
8. **Flag found**: `csd{dn5_m19HT_B3_K1ND4_W0NKy}`
