package com.amdelamar.jhash.util;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;

import java.security.SecureRandom;

/**
 * Hash Utility and Common functions.
 *
 * @author amdelamar
 * @since 1.0.0
 */
public final class HashUtils {

    private HashUtils() {
        // prevent instantiation
    }

    /**
     * Generates a secure random salt of 24 bytes.
     *
     * @return byte array salt
     */
    public static byte[] randomSalt() {
        return randomSalt(new SecureRandom(), 24);
    }

    /**
     * Generates a secure random salt of the specified size.
     *
     * @param size The size of the salt in bytes.
     * @return byte array salt
     */
    public static byte[] randomSalt(int size) {
        return randomSalt(new SecureRandom(), size);
    }

    /**
     * Generates a secure random salt of 24 bytes.
     *
     * @param secureRandom SecureRandom thats hopefully seeded
     * @return byte array salt
     */
    public static byte[] randomSalt(SecureRandom secureRandom) {
        return randomSalt(secureRandom, 24);
    }

    /**
     * Generates a secure random salt of the specified size.
     *
     * @param secureRandom SecureRandom thats hopefully seeded
     * @param size         The size of the salt in bytes.
     * @return byte array salt
     */
    public static byte[] randomSalt(SecureRandom secureRandom, int size) {
        byte[] salt = new byte[size];
        secureRandom.nextBytes(salt);
        return salt;
    }

    /**
     * Compares two byte arrays.
     *
     * @param byteA First byte array.
     * @param byteB Second byte array.
     * @return true if they are equivalent.
     */
    public static boolean slowEquals(byte[] byteA, byte[] byteB) {
        int diff = byteA.length ^ byteB.length;
        for (int i = 0; i < byteA.length && i < byteB.length; i++) {
            diff |= byteA[i] ^ byteB[i];
        }
        return diff == 0;
    }

    /**
     * Decodes a Base64 string to a byte array. A convenience method for Base64 decoder.
     *
     * @param string (in Base64)
     * @return Base64 decoded byte array
     * @see <a href="https://en.wikipedia.org/wiki/Base64">https://en.wikipedia.org/wiki/Base64</a>
     */
    public static byte[] decodeBase64(String string) {
        return Base64.decodeBase64(string);
    }

    /**
     * Encodes a byte array into a Base64 string. A convenience method for Base64 encoder.
     *
     * @param array (byte array)
     * @return Base64 encoded string
     * @see <a href="https://en.wikipedia.org/wiki/Base64">https://en.wikipedia.org/wiki/Base64</a>
     */
    public static String encodeBase64(byte[] array) {
        return StringUtils.newStringUtf8(Base64.encodeBase64(array));
    }

}
