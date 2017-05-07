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

    public static final String PBKDF2_HMACSHA1 = "PBKDF2WithHmacSHA1";
    public static final String PBKDF2_HMACSHA256 = "PBKDF2WithHmacSHA256";

    // These constants may be changed without breaking existing hashes.
    private static final int SALT_BYTE_SIZE = 24;
    private static final int HASH_BYTE_SIZE = 18;
    private static final int PBKDF2_ITERATIONS = 64000;

    // These constants define the encoding and may not be changed.
    private static final int HASH_SECTIONS = 6;
    private static final int HASH_ALGORITHM_INDEX = 0;
    private static final int ITERATION_INDEX = 1;
    private static final int HASH_SIZE_INDEX = 2;
    private static final int PEPPER_INDEX = 3;
    private static final int SALT_INDEX = 4;
    private static final int PBKDF2_INDEX = 5;

    /**
     * Creates a Hash from the given string using PBKDF2 SHA1. Use this to create new user's
     * passwords. Or when they change their password.
     * 
     * @param password
     *            - The password to be salted and hashed.
     * @return A hash String
     * @throws BadOperationException
     * @see https://en.wikipedia.org/wiki/Hash_function
     */
    public static String create(String password) throws BadOperationException {
        return create(password.toCharArray(), "".toCharArray(), PBKDF2_HMACSHA1);
    }

    /**
     * Creates a Hash from the given char array using PBKDF2 SHA1. Use this to create new user's
     * passwords. Or when they change their password.
     * 
     * @param password
     *            - The password to be salted and hashed.
     * @return A hash String
     * @throws BadOperationException
     * @see https://en.wikipedia.org/wiki/Hash_function
     */
    public static String create(char[] password) throws BadOperationException {
        return create(password, "".toCharArray(), PBKDF2_HMACSHA1);
    }

    /**
     * Creates a Hash from the given string using the specified algorithm. Use this to create new
     * user's passwords. Or when they change their password.
     * 
     * @param password
     *            - The password to be salted and hashed.
     * @param algorithm
     *            - Expects Hash.PBKDF2_HMACSHA1 or Hash.PBKDF2_HMACSHA256
     * @return A hash String
     * @throws BadOperationException
     * @see https://en.wikipedia.org/wiki/Hash_function
     */
    public static String create(String password, String algorithm) throws BadOperationException {
        return create(password.toCharArray(), "".toCharArray(), algorithm);
    }

    /**
     * Creates a Hash from the given char array using the specified algorithm. Use this to create
     * new user's passwords. Or when they change their password.
     * 
     * @param password
     *            - The password to be salted and hashed.
     * @param algorithm
     *            - Expects Hash.PBKDF2_HMACSHA1 or Hash.PBKDF2_HMACSHA256
     * @return A hash String
     * @throws BadOperationException
     * @see https://en.wikipedia.org/wiki/Hash_function
     */
    public static String create(char[] password, String algorithm) throws BadOperationException {
        return create(password, "".toCharArray(), algorithm);
    }

    /**
     * Creates a Hash from the given string using the specified algorithm. Use this to create new
     * user's passwords. Or when they change their password.
     * 
     * @param password
     *            - The password to be salted and hashed.
     * @param pepper
     *            - The application-specific
     *            <a href="https://en.wikipedia.org/wiki/Pepper_(cryptography)">pepper</a>.
     * @param algorithm
     *            - Expects Hash.PBKDF2_HMACSHA1 or Hash.PBKDF2_HMACSHA256
     * @return A hash String
     * @throws BadOperationException
     * @see https://en.wikipedia.org/wiki/Hash_function
     */
    public static String create(String password, String pepper, String algorithm)
            throws BadOperationException {
        return create(password.toCharArray(), pepper.toCharArray(), algorithm);
    }

    /**
     * Creates a Hash from the given char array using the specified algorithm. Use this to create
     * new user's passwords. Or when they change their password.
     * 
     * @param password
     *            - The password to be salted and hashed.
     * @param pepper
     *            - The application-specific
     *            <a href="https://en.wikipedia.org/wiki/Pepper_(cryptography)">pepper</a>.
     * @param algorithm
     *            - Expects Hash.PBKDF2_HMACSHA1 or Hash.PBKDF2_HMACSHA256
     * @return A hash String
     * @throws BadOperationException
     * @see https://en.wikipedia.org/wiki/Hash_function
     */
    public static String create(char[] password, char[] pepper, String algorithm)
            throws BadOperationException {
        // Generate a random salt
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_BYTE_SIZE];
        random.nextBytes(salt);

        // add pepper if not empty
        char isPeppered = 'n';
        String pepperPassword = new String(password);
        if (pepper != null && pepper.length > 0) {
            isPeppered = 'y';
            pepperPassword = (new String(pepper) + pepperPassword);
        }

        // Hash the password
        byte[] hash = pbkdf2(pepperPassword.toCharArray(), salt, algorithm, PBKDF2_ITERATIONS,
                HASH_BYTE_SIZE);
        int hashSize = hash.length;

        // format: algorithm:iterations:hashSize:salt:hash
        String parts = PBKDF2_ITERATIONS + ":" + hashSize + ":" + isPeppered + ":"
                + encodeBase64(salt) + ":" + encodeBase64(hash);

        if (algorithm.equals(PBKDF2_HMACSHA1)) {
            parts = "sha1:" + parts;
        } else if (algorithm.equals(PBKDF2_HMACSHA256)) {
            parts = "sha256:" + parts;
        }

        return parts;
    }

    /**
     * Returns true if the string, once hashed, matches the expected hash. Use this to verify a user
     * login. Take the entered password and compare it with the entire hash stored from before.
     * 
     * @param password
     *            - The password to be validated.
     * @param correctHash
     *            - The stored hash from before.
     * @return boolean true if matches
     * @throws BadOperationException
     * @throws InvalidHashException
     * @see https://en.wikipedia.org/wiki/Hash_function
     */
    public static boolean verify(String password, String correctHash)
            throws BadOperationException, InvalidHashException {
        return verify(password.toCharArray(), null, correctHash);
    }

    /**
     * Returns true if the char array, once hashed, matches the expected hash. Use this to verify a
     * user login. Take the entered password and compare it with the entire hash stored from before.
     * 
     * @param password
     *            - The password to be validated.
     * @param correctHash
     *            - The stored hash from before.
     * @return boolean true if matches
     * @throws BadOperationException
     * @throws InvalidHashException
     * @see https://en.wikipedia.org/wiki/Hash_function
     */
    public static boolean verify(char[] password, String correctHash)
            throws BadOperationException, InvalidHashException {
        return verify(password, null, correctHash);
    }

    /**
     * Returns true if the string and
     * <a href="https://en.wikipedia.org/wiki/Pepper_(cryptography)">pepper</a>, once hashed,
     * matches the expected hash. Use this to verify a user login. Take the entered password and
     * compare it with the entire hash stored from before.
     * 
     * @param password
     *            - The password to be validated.
     * @param pepper
     *            - The application-specific
     *            <a href="https://en.wikipedia.org/wiki/Pepper_(cryptography)">pepper</a>.
     * @param correctHash
     *            - The stored hash from before.
     * @return boolean true if matches
     * @throws BadOperationException
     * @throws InvalidHashException
     * @see https://en.wikipedia.org/wiki/Hash_function
     */
    public static boolean verify(String password, String pepper, String correctHash)
            throws BadOperationException, InvalidHashException {
        return verify(password.toCharArray(), pepper.toCharArray(), correctHash);
    }

    /**
     * Returns true if the char array and
     * <a href="https://en.wikipedia.org/wiki/Pepper_(cryptography)">pepper</a>, once hashed,
     * matches the expected hash. Use this to verify a user login. Take the entered password and
     * compare it with the entire hash stored from before.
     * 
     * @param password
     *            - The password to be validated.
     * @param pepper
     *            - The application-specific
     *            <a href="https://en.wikipedia.org/wiki/Pepper_(cryptography)">pepper</a>.
     * @param correctHash
     *            - The stored hash from before.
     * @return boolean true if matches
     * @throws BadOperationException
     * @throws InvalidHashException
     * @see https://en.wikipedia.org/wiki/Hash_function
     */
    public static boolean verify(char[] password, char[] pepper, String correctHash)
            throws BadOperationException, InvalidHashException {
        // Decode the hash into its parameters
        String[] params = correctHash.split(":");
        if (params.length != HASH_SECTIONS) {
            throw new InvalidHashException("Fields are missing from the correct hash.");
        }

        // Currently, only supports SHA1 and SHA256.
        String alg = params[HASH_ALGORITHM_INDEX];
        if (!alg.equals("sha1") && !alg.equals("sha256")) {
            throw new BadOperationException("Unsupported hash type.");
        }
        if (alg.equals("sha1")) {
            alg = PBKDF2_HMACSHA1;
        } else {
            alg = PBKDF2_HMACSHA256;
        }

        int iterations = 0;
        try {
            iterations = Integer.parseInt(params[ITERATION_INDEX]);
        } catch (NumberFormatException ex) {
            throw new InvalidHashException("Could not parse the iteration count as an integer.",
                    ex);
        }

        if (iterations < 1) {
            throw new InvalidHashException("Invalid number of iterations. Must be >= 1.");
        }

        String pepperPassword = new String(password);
        try {
            if ('y' == params[PEPPER_INDEX].charAt(0)) {
                pepperPassword = (new String(pepper) + pepperPassword);
            }
        } catch (IllegalArgumentException ex) {
            throw new InvalidHashException("Could not parse the pepper flag.", ex);
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
        byte[] testHash = pbkdf2(pepperPassword.toCharArray(), salt, alg, iterations, hash.length);
        // Compare the hashes in constant time.
        return slowEquals(hash, testHash);
    }

    private static boolean slowEquals(byte[] byteA, byte[] byteB) {
        int diff = byteA.length ^ byteB.length;
        for (int i = 0; i < byteA.length && i < byteB.length; i++) {
            diff |= byteA[i] ^ byteB[i];
        }
        return diff == 0;
    }

    private static byte[] pbkdf2(char[] string, byte[] salt, String algorithm, int iterations,
            int bytes) throws BadOperationException {
        try {
            PBEKeySpec spec = new PBEKeySpec(string, salt, iterations, bytes * 8);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm);
            return skf.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException ex) {
            throw new BadOperationException("Hash algorithm not supported.", ex);
        } catch (InvalidKeySpecException ex) {
            throw new BadOperationException("Invalid key spec.", ex);
        }
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
