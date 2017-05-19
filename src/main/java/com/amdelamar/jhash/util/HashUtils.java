package com.amdelamar.jhash.util;

import java.security.SecureRandom;
import java.util.Base64;

import com.amdelamar.jhash.Hash;

/**
 * Hash Utility and Common functions.
 * 
 * @author amdelamar
 * @see https://github.com/amdelamar/jhash
 */
public class HashUtils {

    /**
     * Generates a secure random salt of 24 bytes.
     * 
     * @return byte array salt
     */
    public static byte[] randomSalt() {
        return randomSalt(Hash.SALT_BYTE_SIZE);
    }

    /**
     * Generates a secure random salt of the specified size.
     * 
     * @param size
     *            The size of the salt in bytes.
     * @return byte array salt
     */
    public static byte[] randomSalt(int size) {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[size];
        random.nextBytes(salt);
        return salt;
    }

    /**
     * Compares two byte arrays.
     * 
     * @param byteA
     *            First byte array.
     * @param byteB
     *            Second byte array.
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
     * Decodes a Base64 string to a byte array. A convenience method for java.util.Base64 decoder.
     * 
     * @param string
     *            (in Base64)
     * @return Base64 decoded byte array
     * @see https://en.wikipedia.org/wiki/Base64
     */
    public static byte[] decodeBase64(String string) {
        return Base64.getDecoder().decode(string);
    }

    /**
     * Encodes a byte array into a Base64 string. A convenience method for java.util.Base64 encoder.
     * 
     * @param array
     *            (byte array)
     * @return Base64 encoded string
     * @see https://en.wikipedia.org/wiki/Base64
     */
    public static String encodeBase64(byte[] array) {
        return new String(Base64.getEncoder().encode(array));
    }

}
