package com.amdelamar.jhash.algorithms;

/**
 * Hash Type enumeration constant
 *
 * @author amdelamar
 * @since 1.1.0
 */
public enum Type {

    /**
     * PBKDF2 with Hmac SHA1 Type constant
     */
    PBKDF2_SHA1,

    /**
     * PBKDF2 with Hmac SHA256 Type constant
     */
    PBKDF2_SHA256,

    /**
     * PBKDF2 with Hmac SHA512 Type constant
     */
    PBKDF2_SHA512,

    /**
     * BCrypt Type constant
     */
    BCRYPT,

    /**
     * SCrypt Type constant
     */
    SCRYPT
}
