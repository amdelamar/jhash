# JHash

Password hashing utility in Java.

---


## Usage

This code salts and hashes passwords with PBKDF2 (64,000 iterations of SHA1 by default).

`createHash(password)` gives you a salt+hash of the password. Store it somewhere safe.

`verify(password, correctHash)` returns true, if the string password matches the hashed password.


## Customize

- `PBKDF2_HASH_ALGORITHM`: The hash function PBKDF2 uses. By default, it is SHA1
  for compatibility across implementations, but you may change it to SHA256 if
  you don't care about compatibility. Although SHA1 has been cryptographically
  broken as a collision-resistant function, it is still perfectly safe for
  password storage with PBKDF2.

- `PBKDF2_ITERATIONS`: The number of PBKDF2 iterations. By default, it is
  32,000. To provide greater protection of passwords, at the expense of needing
  more processing power to validate passwords, increase the number of
  iterations. The number of iterations should not be decreased.

- `PBKDF2_SALT_BYTES`: The number of bytes of salt. By default, 24 bytes, which
  is 192 bits. This is more than enough. This constant should not be changed.

- `PBKDF2_HASH_BYTES`: The number of PBKDF2 output bytes. By default, 18 bytes,
  which is 144 bits. While it may seem useful to increase the number of output
  bytes, doing so can actually give an advantage to the attacker, as it
  introduces unnecessary (avoidable) slowness to the PBKDF2 computation. 144
  bits was chosen because it is (1) Less than SHA1's 160-bit output (to avoid
  unnecessary PBKDF2 overhead), and (2) A multiple of 6 bits, so that the base64
  encoding is optimal.

Note that these constants are encoded into the hash string when it is created
with `CreateHash` so that they can be changed without breaking existing hashes.
The new (changed) values will apply only to newly-created hashes.


## Hash Format

The hash format is five fields separated by the colon (':') character.

```
algorithm:iterations:hashSize:salt:hash
```

Where:

- `algorithm` is the name of the cryptographic hash function ("sha1").
- `iterations` is the number of PBKDF2 iterations ("64000").
- `hashSize` is the length, in bytes, of the `hash` field (after decoding).
- `salt` is the salt, base64 encoded.
- `hash` is the PBKDF2 output, base64 encoded. It must encode `hashSize` bytes.

Examples:

```
sha1:64000:18:B6oWbvtHvu8qCgoE75wxmvpidRnGzGFt:R1gkPOuVjqIoTulWP1TABS0H
sha1:64000:18:/GO9XQOPexBFVzRjC9mcOkVEi7ZHQc0/:0mY83V5PvmkkHRR41R1iIhx/
sha1:64000:18:rxGkJ9fMTNU7ezyWWqS7QBOeYKNUcVYL:tn+Zr/xo99LI+kSwLOUav72X
sha1:64000:18:lFtd+Qf93yfMyP6chCxJP5nkOxri6Zbh:B0awZ9cDJCTdfxUVwVqO+Mb5
```


## Details

This code uses the PBKDF2 algorithm to protect passwords. Better technologies
for protecting passwords exist today, like bcrypt, scrypt, or Argon2. Before
using this code, you should try to find a well-reviewed and carefully-made
implementation of one of those algorithms for the language that you are using.
These algorithms are "memory hard," meaning that they don't just need a lot of
CPU power to compute, they also require a lot of memory (unlike PBKDF2). By
using a memory hard algorithm, your passwords will be better protected.

One thing you could do would be to use
[libsodium](https://github.com/jedisct1/libsodium) to [hash your passwords with
scrypt](https://download.libsodium.org/doc/password_hashing/index.html). It has
bindings available for many languages.

Since there are better options, this code is now in "maintenance mode." Only
bugs will be fixed, no new features will be added. It is currently safe to use,
but using libsodium would be better.

## License

[MIT](https://github.com/amdelamar/jhash/blob/master/LICENSE)