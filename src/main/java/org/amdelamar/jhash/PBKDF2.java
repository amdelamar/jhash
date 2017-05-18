package org.amdelamar.jhash;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.amdelamar.jhash.exception.BadOperationException;

/**
 * PBKDF2 implements the password-based key derivative function 2, for password hashing. It follows
 * the PKCS public key cryptography standards #5 v2.0. (RFC 2898).
 * 
 * @author amdelamar
 * @see https://en.wikipedia.org/wiki/PBKDF2
 * @see https://tools.ietf.org/html/rfc2898
 */
public class PBKDF2 {

    public static final int ITERATIONS = 64000;

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
     * @param bytes
     *            - The length of the hash in bytes.
     * @return A hash String
     * @throws NoSuchAlgorithmException
     *             if algorithm not supported
     * @throws BadOperationException
     *             if key spec is invalid
     */
    public static byte[] create(char[] password, byte[] salt, String algorithm, int iterations,
            int bytes) throws NoSuchAlgorithmException, BadOperationException {
        
        if(password == null || password.length == 0) {
            throw new BadOperationException("Password cannot be null or empty!");
        }

        // strengthen weak choices from users
        if (iterations < 1000)
            iterations = ITERATIONS;

        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bytes * 8);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm);
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException ex) {
            throw new NoSuchAlgorithmException("Hash algorithm not supported.", ex);
        } catch (InvalidKeySpecException ex) {
            throw new BadOperationException("Invalid key spec.", ex);
        }
    }
}
