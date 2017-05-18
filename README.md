# Jhash

[![Build](https://travis-ci.org/amdelamar/jhash.svg?branch=master)](https://travis-ci.org/amdelamar/jhash)
[![Code Climate](https://codeclimate.com/github/amdelamar/jhash/badges/gpa.svg)](https://codeclimate.com/github/amdelamar/jhash)
[![License](https://img.shields.io/:license-BSD2-blue.svg)](https://github.com/amdelamar/jhash/blob/master/LICENSE)

Password hashing utility in Java. It can hash passwords with PBKDF2 hmac SHA1/SHA256/SHA512, BCRYPT, or SCRYPT, and it salts automatically and has a pepper option. 


## Getting Started

* Maven `coming soon`.
* Gradle `coming soon`.
* Download Jar `coming soon`.


```
// salt + hash a password. (pbkdf2 hmac sha1)
String hash = Hash.create(password);

// Verify Login 
boolean login = Hash.verify(password, correctHash);
// Returns true, if the password matches the hashed password.
// If you use another algorithm, you don't need to specify it in the verify() method.


// More Options:

// pbkdf2 hmac sha512
String hash = Hash.create(password, Hash.PBKDF2_HMACSHA512);
// Returns: sha512:64000:18:n:EbroMczUKuBRx5sy+hgFQyHmqk2iNtt5:Ml8pGxc3pYoh1z5fkk5rfjM9

// pbkdf2 hmac sha256 + pepper
String hash = Hash.create(password, pepper, Hash.PBKDF2_HMACSHA256);
// Returns: sha256:64000:18:y:J84o+zGuJebtj99FiAMk9pminEBmoEIm:4hoNRxgrn79lxujYIrNUXQd1

// pbkdf2 hmac sha512 + pepper
String hash = Hash.create(password, pepper, Hash.PBKDF2_HMACSHA512);
// Returns: sha512:64000:18:y:v+tqRNA5B4cAxbZ4aUId/hvrR+FlS1d8:/R851fqvd7HItsSr0vJEupBf

// bcrypt + pepper
String hash = Hash.create(password, pepper, Hash.BCRYPT);
// Returns: bcrypt:10:66:y::$2a$10$UlxpnyYwYmmlLgl7YVGonN9H74ffEttiD1O2uMy8q5Y7YgJc8.YsRa3yOM6

// scrypt no pepper
String hash = Hash.create(password, Hash.SCRYPT);
// Returns: scrypt:16384:79:n::$s0$e0801$+nNFxTV9IHyN0cPKn/ORDA==$uPrBpPBQm7GgX+Vcc/8zuFNJZ+8XqDMylpLrOjv6X8w=

// scrypt + pepper
String hash2 = Hash.create(password, pepper, Hash.SCRYPT);
// Returns: scrypt:16384:79:y::$s0$e0801$iHSTF05OtGCb3BiaFTZ3BA==$QANWx2qBzMzONIQEXUJTWnNX+3wynikSkGJdO9QvOx8=
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
bcrypt:13:66:n::$2a$10$YQ9urAM3RKuDtl1XaF99HrdpoIlB6ZhfaGR1T4yS4jlfMSPyeXehE.0Dway
bcrypt:13:66:y::$2a$10$sdreyOHQW0XAGw.LMXbPyayMMGlMuU69htdw8KXjzk5xOrVTFj2aYLxre7y
scrypt:131072:79:n::$s0$e0801$Evw8WPqcEUy1n3PhZcP9pg==$lRbNPFoOdoBMFT0XUcZUPvIxCY8w+9DkUklXIqCOHks=
scrypt:131072:79:y::$s0$e0801$mzUhOD/ns1JCnwhsYPvIkg==$OlipMfOQJkCm62kY1m79AgIsfPzmIDdgz/fl/68EQ+Y=
```

- `algorithm` is the name of the cryptographic hash function.
- `iterations` is the number of iterations (PBKDF2 64000, BCRYPT 2<sup>12</sup>, SCRYPT cpu cost).
- `hashSize` is the length, in bytes, of the `hash` field (after decoding).
- `pepper` is an indicator that a pepper was used ("y" or "n").
- `salt` is the salt. (BCRYPT and SCRYPT salt is embeded in the hash). 
- `hash` is the hash.


## Options and Considerations

#### PBKDF2 Options

You have three options with PBKDF2 hmac: SHA1, SHA256, or SHA512. Test each before you try them, because not all JVM's support the newer hashing methods. Java 8 added support for PBKDF2 with SHA512 in 2014.

The default iterations = 64,000 but feel free to increase up to 200,000 depending on your server and cpu cost you want. Run some preliminary tests to find out if hashes are too quick. You'll want **at least 0.5 seconds** per hash and no faster.


#### BCrypt Options

The default logrounds = 13 but feel free to increase up to 20 depending on the cpu cost you want. Again, run some preliminary tests to find out if hashes are too quick. Here is a quick estimate:

* 12 = About ~250 ms each hash.
* 13 = About ~500 ms each hash. :key: 
* 14 = About ~1 second each hash.
* 15 = About ~2 seconds each hash.
* 16 = About ~4.5 seconds each hash.

Also note that BCrypt has a password limit of 72 characters (18 32-bit words). Be sure to truncate before hashing. Its a limitiation of the Blowfish cipher.


#### SCrypt Options

The default cost = 131072 (2<sup>17</sup>) but you can increase this too. Again, run some preliminary tests to find out if the hashes are computed too quickly. Here is a quick estimate:

* 16384  (2<sup>15</sup>) = About ~100 ms each hash.
* 131072 (2<sup>17</sup>) = About ~800 ms each hash :key: 
* 262144  (2<sup>18</sup>) = About ~2 seconds each hash.
* 1048576 (2<sup>20</sup>) = About ~5 seconds each hash.



## Details

By default, if you just call `Hash.create(pwd)` it uses PBKDF2 hmac SHA1 with 24 bytes (192 bits) of securely random salt and outputs 18 bytes (144 bits). 144 bits was chosen because it is (1) Less than SHA1's 160-bit output (to avoid unnecessary PBKDF2 overhead), and (2) A multiple of 6 bits, so that the base64 encoding is optimal. PBKDF2 hmac SHA1 was chosen for the default mainly for the most compatibility across Java implementations. Although SHA1 has been cryptographically broken as a collision-resistant function, it is still perfectly safe for password storage with PBKDF2. Its my recommendation though to use algorithms like BCRYPT and SCRYPT. As they are 'memory hard', meaning that they don't just need a lot of CPU power to compute, they also require a lot of memory (unlike PBKDF2). This makes them better against brute-force attacks.


## Credit

A project by [Austin Delamar](https://github.com/amdelamar) based off of [Taylor Hornby](https://github.com/defuse/password-hashing) and [Damien Miller](https://github.com/jeremyh/jBCrypt)'s work and other [contributors](https://github.com/amdelamar/jhash/graphs/contributors).


## License

PBKDF2 is licensed as [BSD-2-Clause](https://github.com/amdelamar/jhash/blob/master/LICENSE)

BCRYPT is licensed as [ISC](https://github.com/amdelamar/jhash/blob/master/LICENSE)

SCRYPT is licensed as [Apache 2.0](https://github.com/amdelamar/jhash/blob/master/LICENSE)
