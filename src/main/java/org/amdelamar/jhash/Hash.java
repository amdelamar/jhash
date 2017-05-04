package org.amdelamar.jhash;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.amdelamar.jhash.exception.BadOperationException;
import org.amdelamar.jhash.exception.InvalidHashException;

public class Hash {

    public static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA1";

    // These constants may be changed without breaking existing hashes.
    public static final int SALT_BYTE_SIZE = 24;
    public static final int HASH_BYTE_SIZE = 18;
    public static final int PBKDF2_ITERATIONS = 64000;

    // These constants define the encoding and may not be changed.
    public static final int HASH_SECTIONS = 5;
    public static final int HASH_ALGORITHM_INDEX = 0;
    public static final int ITERATION_INDEX = 1;
    public static final int HASH_SIZE_INDEX = 2;
    public static final int SALT_INDEX = 3;
    public static final int PBKDF2_INDEX = 4;

    public static String create(String password) throws BadOperationException {
        return create(password.toCharArray());
    }

    public static String create(char[] password) throws BadOperationException {
        // Generate a random salt
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_BYTE_SIZE];
        random.nextBytes(salt);

        // Hash the password
        byte[] hash = pbkdf2(password, salt, PBKDF2_ITERATIONS, HASH_BYTE_SIZE);
        int hashSize = hash.length;

        // format: algorithm:iterations:hashSize:salt:hash
        String parts = "sha1:" + PBKDF2_ITERATIONS + ":" + hashSize + ":" + encodeBase64(salt) + ":" + encodeBase64(hash);
        return parts;
    }

    public static boolean verify(String string, String correctHash)
            throws BadOperationException, InvalidHashException {
        return verify(string.toCharArray(), correctHash);
    }

    public static boolean verify(char[] string, String correctHash)
            throws BadOperationException, InvalidHashException {
        // Decode the hash into its parameters
        String[] params = correctHash.split(":");
        if (params.length != HASH_SECTIONS) {
            throw new InvalidHashException("Fields are missing from the correct hash.");
        }

        // Currently, Java only supports SHA1.
        if (!params[HASH_ALGORITHM_INDEX].equals("sha1")) {
            throw new BadOperationException("Unsupported hash type.");
        }

        int iterations = 0;
        try {
            iterations = Integer.parseInt(params[ITERATION_INDEX]);
        } catch (NumberFormatException ex) {
            throw new InvalidHashException("Could not parse the iteration count as an integer.", ex);
        }

        if (iterations < 1) {
            throw new InvalidHashException("Invalid number of iterations. Must be >= 1.");
        }

        byte[] salt = null;
        try {
            salt = decodeBase64(params[SALT_INDEX]);
        } catch (IllegalArgumentException ex) {
            throw new InvalidHashException("Base64 decoding of salt failed.", ex);
        }

        byte[] hash = null;
        try {
            hash = decodeBase64(params[PBKDF2_INDEX]);
        } catch (IllegalArgumentException ex) {
            throw new InvalidHashException("Base64 decoding of pbkdf2 output failed.", ex);
        }

        int storedHashSize = 0;
        try {
            storedHashSize = Integer.parseInt(params[HASH_SIZE_INDEX]);
        } catch (NumberFormatException ex) {
            throw new InvalidHashException("Could not parse the hash size as an integer.", ex);
        }

        if (storedHashSize != hash.length) {
            throw new InvalidHashException("Hash length doesn't match stored hash length.");
        }

        // Compute the hash of the provided string, using the same salt,
        // iteration count, and hash length
        byte[] testHash = pbkdf2(string, salt, iterations, hash.length);
        // Compare the hashes in constant time.
        return slowEquals(hash, testHash);
    }

    private static boolean slowEquals(byte[] a, byte[] b) {
        int diff = a.length ^ b.length;
        for (int i = 0; i < a.length && i < b.length; i++)
            diff |= a[i] ^ b[i];
        return diff == 0;
    }

    private static byte[] pbkdf2(char[] string, byte[] salt, int iterations, int bytes) throws BadOperationException {
        try {
            PBEKeySpec spec = new PBEKeySpec(string, salt, iterations, bytes * 8);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException ex) {
            throw new BadOperationException("Hash algorithm not supported.", ex);
        } catch (InvalidKeySpecException ex) {
            throw new BadOperationException("Invalid key spec.", ex);
        }
    }
    
    /**
     * Decodes a Base64 string to a byte array.
     * @param string
     * @return
     */
    private static byte[] decodeBase64(String string) {
        return Base64.getDecoder().decode(string);
    }
    
    /**
     * Encodes a byte array into a Base64 string.
     * @param array
     * @return
     */
    private static String encodeBase64(byte[] array) {
        return new String(Base64.getEncoder().encode(array));
    }

}
