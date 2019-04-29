# Jhash

[![Build](https://img.shields.io/travis/amdelamar/jhash.svg)](https://travis-ci.org/amdelamar/jhash)
[![Codacy](https://img.shields.io/codacy/grade/6d7927e4c18042d6a62f27e8ab5b53dd.svg)](https://www.codacy.com/app/amdelamar/jhash)
[![Codecov](https://img.shields.io/codecov/c/github/amdelamar/jhash.svg)](https://codecov.io/gh/amdelamar/jhash)
[![Known Vulnerabilities](https://snyk.io/test/github/amdelamar/jhash/badge.svg)](https://snyk.io/test/github/amdelamar/jhash)

Password hashing utility in Java. It can hash passwords with PBKDF2 hmac SHA1/SHA256/SHA512, BCRYPT, or SCRYPT, and it salts automatically and has a pepper option.


## Download

Maven:

```xml
<repositories>
    <repository>
        <id>jcenter</id>
        <url>https://jcenter.bintray.com/</url>
    </repository>
</repositories>

<dependency>
    <groupId>com.amdelamar</groupId>
    <artifactId>jhash</artifactId>
    <version>2.1.0</version>
</dependency>
```

Gradle:

```gradle
repositories {
    jcenter()
}

dependencies {
    compile 'com.amdelamar:jhash:2.1.0'
}
```

Or Download the [latest release](https://github.com/amdelamar/jhash/releases). Published on [JCenter](https://bintray.com/amdelamar/mvn/jhash).


## Usage

Easy hash and verification...

```java
import com.amdelamar.jhash.Hash;

char[] password = "Hello World!".toCharArray();

// salt + hash a password. (pbkdf2 hmac sha1)
String hash = Hash.password(password).create();
// Example: pbkdf2sha1:64000:18:24:n:LZXY631xphycV5kaJ2WY0RRDqSfwiZ6L:uOw06jt6FvimXSxEJipYYHsQ

// Save the enitre string somewhere safe...

// Verify Login
if(Hash.password(password).verify(correctHash)) {
    // Passwords match. Login successful!
}
```

More Options...

```java
// pbkdf2 hmac sha512 + salt
String hash = Hash.password(password).algorithm(Type.PBKDF2_SHA512).create();
// Returns: pbkdf2sha512:64000:18:24:n:EbroMczUKuBRx5sy+hgFQyHmqk2iNtt5:Ml8pGxc3pYoh1z5fkk5rfjM9

// pbkdf2 hmac sha256 + salt + pepper
String hash = Hash.password(password).pepper(pepper).algorithm(Type.PBKDF2_SHA256).create();
// Returns: pbkdf2sha256:64000:18:24:y:J84o+zGuJebtj99FiAMk9pminEBmoEIm:4hoNRxgrn79lxujYIrNUXQd1

// pbkdf2 hmac sha512 + salt + pepper + higher salt length
String hash = Hash.password(password).pepper(pepper).algorithm(Type.PBKDF2_SHA512).saltLength(36).create();
// Returns: pbkdf2sha512:64000:18:36:y:v+tqRNA5B4cAxbZ4aUId/hvrR+FlS1d8:/R851fqvd7HItsSr0vJEupBf

// bcrypt + salt
String hash = Hash.password(password).algorithm(Type.BCRYPT).create();
// Example: bcrypt:13:66:16:n::$2a$10$YQ9urAM3RKuDtl1XaF99HrdpoIlB6ZhfaGR1T4yS4jlfMSPyeXehE.0Dway

// bcrypt + salt + pepper
String hash = Hash.password(password).pepper(pepper).algorithm(Type.BCRYPT).create();
// Example: bcrypt:13:66:16:y::$2a$10$UlxpnyYwYmmlLgl7YVGonN9H74ffEttiD1O2uMy8q5Y7YgJc8.YsRa3yOM6

// scrypt + salt
String hash = Hash.password(password).algorithm(Type.SCRYPT).create();
// Example: scrypt:16384:80:24:n::$s0$e0801$+nNFxTV9IHyN0cPKn/ORDA==$uPrBpPBQm7GgX+Vcc/8zuFNJZ+8XqDMylpLrOjv6X8w=

// scrypt + salt + pepper
String hash = Hash.password(password).pepper(pepper).algorithm(Type.SCRYPT).create();
// Example: scrypt:16384:80:24:y::$s0$e0801$iHSTF05OtGCb3BiaFTZ3BA==$QANWx2qBzMzONIQEXUJTWnNX+3wynikSkGJdO9QvOx8=

// scrypt + salt + pepper + higher complexity factor
String hash = Hash.password(password).pepper(pepper).algorithm(Type.SCRYPT).factor(1048576).create();
// Example: scrypt:16384:80:24:y::$s0$e0801$iHSTF05OtGCb3BiaFTZ3BA==$QANWx2qBzMzONIQEXUJTWnNX+3wynikSkGJdO9QvOx8=
```

Now verify the passwords match. Even if you use a stronger algorithm, longer salt length, or increase the complexity factor, you don't need to provide that information when you `verify()` because the hash output has those values already. But if you used a pepper, you need to provide that when verifying.

```java
// Verify Login
if(Hash.password(password).verify(correctHash)) {
    // Passwords match. Login successful!
}

// Provide the pepper if you used one.
// (This is because the pepper isn't stored with the hash!)
if(Hash.password(password).pepper(pepper).verify(correctHash)) {
    // Passwords match. Login successful!
}
```

## Hash Format

The hash format is seven fields separated by the colon (':') character.

`algorithm:factor:hashLength:saltLength:pepper:salt:hash`

Examples:

```
pbkdf2sha1:64000:18:24:n:LZXY631xphycV5kaJ2WY0RRDqSfwiZ6L:uOw06jt6FvimXSxEJipYYHsQ
pbkdf2sha256:64000:18:24:n:ZhxPG2klUysxywJ7NIAhFNTtEKa1U2yu:6oeoGuoQAOIKsztgIgPHTC4/
pbkdf2sha256:64000:18:24:y:8MD0yEl5DKz+8Av2L8985h63BhvVppYU:osTwsDh2qo/wgE6g0BrjdeFt
pbkdf2sha512:64000:18:24:n:EbroMczUKuBRx5sy+hgFQyHmqk2iNtt5:Ml8pGxc3pYoh1z5fkk5rfjM9
pbkdf2sha512:64000:18:24:y:v+tqRNA5B4cAxbZ4aUId/hvrR+FlS1d8:/R851fqvd7HItsSr0vJEupBf
bcrypt:13:66:16:n::$2a$10$YQ9urAM3RKuDtl1XaF99HrdpoIlB6ZhfaGR1T4yS4jlfMSPyeXehE.0Dway
bcrypt:13:66:16:y::$2a$10$sdreyOHQW0XAGw.LMXbPyayMMGlMuU69htdw8KXjzk5xOrVTFj2aYLxre7y
scrypt:131072:24:80:n::$s0$e0801$Evw8WPqcEUy1n3PhZcP9pg==$lRbNPFoOdoBMFT0XUcZUPvIxCY8w+9DkUklXIqCOHks=
scrypt:131072:24:80:y::$s0$e0801$mzUhOD/ns1JCnwhsYPvIkg==$OlipMfOQJkCm62kY1m79AgIsfPzmIDdgz/fl/68EQ+Y=
```

- `algorithm` is the name of the cryptographic hash function.
- `factor` parameter for the function. PBKDF2 number of iterations (64000), BCRYPT number of logrounds (2<sup>12</sup>), SCRYPT cpu/mem cost (131072).
- `hashLength` is the byte length of the `hash`.
- `saltLength` is the byte length of the `salt`.
- `pepper` is an indicator that a pepper was used ("y" or "n"). Peppers aren't stored with the Hashes. They're stored in the application properties.
- `salt` is the salt. (Note: BCRYPT and SCRYPT salt is embedded in the hash).
- `hash` is the raw password hash.


## Options and Considerations

#### PBKDF2 Options

You have three options with PBKDF2 hmac: SHA1, SHA256, or SHA512. Test each before you try them, because not all JVM's support the newer hashing methods. Java 8 added support for PBKDF2 with SHA512 in 2014.

The default iterations = 64,000 but feel free to increase up to 200,000 depending on your server and cpu cost you want. Run some preliminary tests to find out if your server/device can handle the high number of iterations first. There are lots of applications out there that use anywhere from 1,000 to 10k, or 200k, for their storage.


#### BCrypt Options

The default logrounds = 13 but feel free to increase up to 20 depending on the cpu cost you want. Again, run some preliminary tests to find out if hashes are too quick. You'll want **at least 0.5 seconds** per hash and no faster. Here is a quick estimate:

* 12 = About ~250 ms each hash.
* 13 = About ~500 ms each hash. :key: default
* 14 = About ~1 second each hash.
* 15 = About ~2 seconds each hash.
* 16 = About ~4.5 seconds each hash.

Also note that BCrypt has a password limit of 72 characters (18 32-bit words). Be sure to truncate before hashing. Its a limitiation of the Blowfish cipher. BCrypt has a default salt length of 16 to remain compatible with the standard formula, but you can increase this if you wish.


#### SCrypt Options

The default cost = 131072 (2<sup>17</sup>) but you can increase this too. Again, run some preliminary tests to find out if the hashes are computed too quickly. You'll want **at least 0.5 seconds** per hash and no faster. Here is a quick estimate:

* 16384  (2<sup>15</sup>) = About ~100 ms each hash.
* 131072 (2<sup>17</sup>) = About ~800 ms each hash :key: default
* 262144  (2<sup>18</sup>) = About ~2 seconds each hash.
* 1048576 (2<sup>20</sup>) = About ~5 seconds each hash.



## Details

By default, if you just call `Hash.password(pwd).create()` it uses PBKDF2 hmac SHA1 with 24 bytes (192 bits) of securely random salt and outputs 18 bytes (144 bits). 144 bits was chosen because it is (1) Less than SHA1's 160-bit output (to avoid unnecessary PBKDF2 overhead), and (2) A multiple of 6 bits, so that the base64 encoding is optimal. PBKDF2 hmac SHA1 was chosen for the default mainly for the most compatibility across Java implementations. Although SHA1 has been cryptographically broken as a collision-resistant function, it is still perfectly safe for password storage with PBKDF2. Its my recommendation though to use algorithms like BCRYPT and SCRYPT. As they are 'memory hard', meaning that they don't just need a lot of CPU power to compute, they also require a lot of memory (unlike PBKDF2). This makes them better against brute-force attacks.


## Contribute

A project by [Austin Delamar](https://github.com/amdelamar) based off of [Taylor Hornby](https://github.com/defuse/password-hashing), [Damien Miller](https://github.com/jeremyh/jBCrypt), and [Will Grozer](https://github.com/wg/scrypt)'s work and other [contributors](https://github.com/amdelamar/jhash/graphs/contributors).

If you'd like to contribute, feel free to fork and make changes, then open a pull request to master branch.


## License

JHash is licensed as [Apache-2.0](https://github.com/amdelamar/jhash/blob/master/LICENSE)

PBKDF2 is licensed as [BSD-2-Clause](https://github.com/amdelamar/jhash/blob/master/LICENSE)

BCRYPT is licensed as [ISC](https://github.com/amdelamar/jhash/blob/master/LICENSE)

SCRYPT is licensed as [Apache-2.0](https://github.com/amdelamar/jhash/blob/master/LICENSE)
