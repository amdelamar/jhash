package com.amdelamar.jhash.algorithms;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * PBKDF2 implements the password-based key derivative function 2, for password hashing. It follows
 * the PKCS public key cryptography standards #5 v2.0. (RFC 2898).
 * 
 * @author amdelamar
 * @see https://en.wikipedia.org/wiki/PBKDF2
 * @see https://tools.ietf.org/html/rfc2898
 */
public class PBKDF2 {

    public static final int DEFAULT_HASH_LENGTH = 18;
    public static final int DEFAULT_SALT_LENGTH = 24;
    public static final int DEFAULT_ITERATIONS = 64000;

    /**
     * Creates a Hash from the given char array using the specified algorithm. Use this to create
     * new user's passwords. Or when they change their password.
     * 
     * @param password
     *            - The password to be salted and hashed.
     * @param salt
     *            - The random <a href="https://en.wikipedia.org/wiki/Salt_(cryptography)">salt</a>.
     * @param algorithm
     *            - Expects Hash.PBKDF2_HMACSHA1, SHA256, or SHA512
     * @param iterations
     *            - The number of iterations of the algorithm.
     * @param hashSize
     *            - The length of the hash in bytes.
     * @return A hash String
     * @throws IllegalArgumentException
     *             if one or more parameters are invalid
     */
    public static byte[] create(char[] password, byte[] salt, String algorithm, int iterations, int hashSize)
            throws IllegalArgumentException {

        if (iterations < 1000) {
            // strengthen weak choices from users
            iterations = DEFAULT_ITERATIONS;
        }

        try {
            // hash
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, hashSize * 8);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm);
            return skf.generateSecret(spec)
                    .getEncoded();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalArgumentException("Hash algorithm not supported.", ex);
        } catch (InvalidKeySpecException ex) {
            throw new IllegalArgumentException("Invalid key spec.", ex);
        }
    }
}
