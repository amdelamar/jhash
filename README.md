# Jhash

[![Build](https://travis-ci.org/amdelamar/jhash.svg?branch=master)](https://travis-ci.org/amdelamar/jhash)
[![Code Climate](https://codeclimate.com/github/amdelamar/jhash/badges/gpa.svg)](https://codeclimate.com/github/amdelamar/jhash)
[![License](https://img.shields.io/:license-BSD2-blue.svg)](https://github.com/amdelamar/jhash/blob/master/LICENSE)

Password hashing utility in Java. It salts automatically and has a pepper option. It hashes passwords with PBKDF2 using 64,000 iterations of SHA1 (default) or SHA256.


## Getting Started

* Maven `coming soon`.
* Gradle `coming soon`.
* Zip with examples `coming soon`.


```
// salt + hash a password. Store it somewhere safe!
String hash = Hash.create(password);

// Test a password
boolean login = Hash.verify(password, correctHash);
// returns true, if the password matches the hashed password.


// More Options...
// sha1
String hash1 = Hash.create(password,Hash.PBKDF2_HMACSHA1);
// Returns: sha1:64000:18:n:LZXY631xphycV5kaJ2WY0RRDqSfwiZ6L:uOw06jt6FvimXSxEJipYYHsQ

// sha256
String hash2 = Hash.create(password,Hash.PBKDF2_HMACSHA256);
// Returns: sha256:64000:18:n:ZhxPG2klUysxywJ7NIAhFNTtEKa1U2yu:6oeoGuoQAOIKsztgIgPHTC4/

// sha1 + pepper
String hash3 = Hash.create(password,pepper,Hash.PBKDF2_HMACSHA1);
// Returns: sha1:64000:18:y:N5uyQzneM1wAMQNx6ZAF8zSdPuK7B8BL:VOWk8jiQv27N5vLWtT6leniL

// sha256 + pepper
String hash4 = Hash.create(password,pepper,Hash.PBKDF2_HMACSHA256);
// Returns: sha256:64000:18:y:8MD0yEl5DKz+8Av2L8985h63BhvVppYU:osTwsDh2qo/wgE6g0BrjdeFt
```


## Hash Format

The hash format is six fields separated by the colon (':') character.

```
algorithm:iterations:hashSize:pepper:salt:hash
```

Examples:

```
sha1:64000:18:n:LZXY631xphycV5kaJ2WY0RRDqSfwiZ6L:uOw06jt6FvimXSxEJipYYHsQ
sha256:64000:18:n:ZhxPG2klUysxywJ7NIAhFNTtEKa1U2yu:6oeoGuoQAOIKsztgIgPHTC4/
sha1:64000:18:y:N5uyQzneM1wAMQNx6ZAF8zSdPuK7B8BL:VOWk8jiQv27N5vLWtT6leniL
sha256:64000:18:y:8MD0yEl5DKz+8Av2L8985h63BhvVppYU:osTwsDh2qo/wgE6g0BrjdeFt
```

- `algorithm` is the name of the cryptographic hash function ("sha1" or "sha256").
- `iterations` is the number of PBKDF2 iterations ("64000").
- `hashSize` is the length, in bytes, of the `hash` field (after decoding).
- `pepper` is an indicator that a pepper was used ("y" or "n").
- `salt` is the salt, base64 encoded.
- `hash` is the PBKDF2 output, base64 encoded. It must encode `hashSize` bytes.


## Details

This code uses PBKDF2 with 24 bytes (192 bits) of securely random salt and outputs 18 bytes (144 bits).  144 bits was chosen because it is (1) Less than SHA1's 160-bit output (to avoid unnecessary PBKDF2 overhead), and (2) A multiple of 6 bits, so that the base64 encoding is optimal.

By default, SHA1 is used for compatibility across implementations, but you may change it to SHA256 if you don't care about compatibility. Although SHA1 has been cryptographically broken as a collision-resistant function, it is still perfectly safe for password storage with PBKDF2.

This code uses the PBKDF2 algorithm to protect passwords. Better technologies for protecting passwords exist today, like bcrypt, scrypt, or Argon2. Before using this code, you should try to find a well-reviewed and carefully-made implementation of one of those algorithms for the language that you are using. These algorithms are "memory hard," meaning that they don't just need a lot of CPU power to compute, they also require a lot of memory (unlike PBKDF2). By using a memory hard algorithm, your passwords will be better protected.

One thing you could do would be to use [libsodium](https://github.com/jedisct1/libsodium) to [hash your passwords with scrypt](https://download.libsodium.org/doc/password_hashing/index.html). It has bindings available for many languages.


## Credit

A project by [Austin Delamar](https://github.com/amdelamar) based off of [Taylor Hornby's work](https://github.com/defuse/password-hashing) and other [contributors](https://github.com/amdelamar/jhash/graphs/contributors).


## License

[BSD-2-Clause](https://github.com/amdelamar/jhash/blob/master/LICENSE)
