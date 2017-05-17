# Jhash

[![Build](https://travis-ci.org/amdelamar/jhash.svg?branch=master)](https://travis-ci.org/amdelamar/jhash)
[![Code Climate](https://codeclimate.com/github/amdelamar/jhash/badges/gpa.svg)](https://codeclimate.com/github/amdelamar/jhash)
[![License](https://img.shields.io/:license-BSD2-blue.svg)](https://github.com/amdelamar/jhash/blob/master/LICENSE)

Password hashing utility in Java. It salts automatically and has a pepper option. It can hash passwords with PBKDF2 SHA1, SHA256, SHA512, or BCRYPT. (Scrypt coming soon.)


## Getting Started

* Maven `coming soon`.
* Gradle `coming soon`.
* Zip with examples `coming soon`.


```
// salt + hash a password. (sha1 default) Store it somewhere safe!
String hash = Hash.create(password);

// Login 
boolean login = Hash.verify(password, correctHash);
// returns true, if the password matches the hashed password.
// If you use another algorithm, you don't need to specify it in the verify() method.


// More Options:

// sha512
String hash = Hash.create(password,Hash.PBKDF2_HMACSHA512);
// Returns: sha512:64000:18:n:EbroMczUKuBRx5sy+hgFQyHmqk2iNtt5:Ml8pGxc3pYoh1z5fkk5rfjM9

// sha256 + pepper
String hash = Hash.create(password,pepper,Hash.PBKDF2_HMACSHA256);
// Returns: sha256:64000:18:y:J84o+zGuJebtj99FiAMk9pminEBmoEIm:4hoNRxgrn79lxujYIrNUXQd1

// sha512 + pepper
String hash = Hash.create(password,pepper,Hash.PBKDF2_HMACSHA512);
// Returns: sha512:64000:18:y:v+tqRNA5B4cAxbZ4aUId/hvrR+FlS1d8:/R851fqvd7HItsSr0vJEupBf

// bcrypt + pepper
String hash = Hash.create(password,pepper,Hash.BCRYPT);
// Returns: bcrypt:10:66:y::$2a$10$UlxpnyYwYmmlLgl7YVGonN9H74ffEttiD1O2uMy8q5Y7YgJc8.YsRa3yOM6
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
sha256:64000:18:y:8MD0yEl5DKz+8Av2L8985h63BhvVppYU:osTwsDh2qo/wgE6g0BrjdeFt
sha512:64000:18:n:EbroMczUKuBRx5sy+hgFQyHmqk2iNtt5:Ml8pGxc3pYoh1z5fkk5rfjM9
sha512:64000:18:y:v+tqRNA5B4cAxbZ4aUId/hvrR+FlS1d8:/R851fqvd7HItsSr0vJEupBf
bcrypt:10:66:n::$2a$10$YQ9urAM3RKuDtl1XaF99HrdpoIlB6ZhfaGR1T4yS4jlfMSPyeXehE.0Dway
bcrypt:10:66:y::$2a$10$sdreyOHQW0XAGw.LMXbPyayMMGlMuU69htdw8KXjzk5xOrVTFj2aYLxre7y
```

- `algorithm` is the name of the cryptographic hash function.
- `iterations` is the number of iterations (PBKDF2 64000, BCRYPT 2<sup>10</sup>, etc).
- `hashSize` is the length, in bytes, of the `hash` field (after decoding).
- `pepper` is an indicator that a pepper was used ("y" or "n").
- `salt` is the salt, base64 encoded (BCRYPT's salt is embeded in the hash). 
- `hash` is the hash, base64 encoded.


## Details

By default, this code uses PBKDF2 HMAC SHA1 with 24 bytes (192 bits) of securely random salt and outputs 18 bytes (144 bits). 144 bits was chosen because it is (1) Less than SHA1's 160-bit output (to avoid unnecessary PBKDF2 overhead), and (2) A multiple of 6 bits, so that the base64 encoding is optimal. You can use the "bcrypt" algorithm by passing Hash.BCRYPT as the algorithm. It uses a cost parameter of 2<sup>10</sup> and the same salt size as before.

PBKDF2 HMAC SHA1 was chosen for the default mainly for compatibility across implementations, but you may change it to SHA256, SHA512, or BCRYPT. Although SHA1 has been cryptographically broken as a collision-resistant function, it is still perfectly safe for password storage with PBKDF2. Algorithms like BCRYPT and SCRYPT are 'memory hard', meaning that they don't just need a lot of CPU power to compute, they also require a lot of memory (unlike PBKDF2). This makes them better against brute-force attacks.

This code has no dependencies on any third-party libraries.


## Credit

A project by [Austin Delamar](https://github.com/amdelamar) based off of [Taylor Hornby](https://github.com/defuse/password-hashing) and [Damien Miller](https://github.com/jeremyh/jBCrypt)'s work and other [contributors](https://github.com/amdelamar/jhash/graphs/contributors).


## License

PBKDF2 is licensed as [BSD-2-Clause](https://github.com/amdelamar/jhash/blob/master/LICENSE)

BCRYPT is licensed as [ISC](https://github.com/amdelamar/jhash/blob/master/LICENSE)
