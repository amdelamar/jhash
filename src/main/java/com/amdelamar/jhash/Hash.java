package com.amdelamar.jhash;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import com.amdelamar.jhash.exception.BadOperationException;
import com.amdelamar.jhash.exception.InvalidHashException;

/**
 * Password hashing utility in Java. It salts automatically and has a pepper option. It hashes
 * passwords with PBKDF2 using 64,000 iterations of SHA1 (default), SHA256, or SHA512.
 * 
 * @author amdelamar
 * @see https://github.com/amdelamar/jhash
 */
public class Hash {

    // algorithms
    public static final String SCRYPT = "scrypt";
    public static final String BCRYPT = "bcrypt";
    public static final String PBKDF2_HMACSHA1 = "PBKDF2WithHmacSHA1";
    public static final String PBKDF2_HMACSHA256 = "PBKDF2WithHmacSHA256";
    public static final String PBKDF2_HMACSHA512 = "PBKDF2WithHmacSHA512";

    // These constants may be changed without breaking existing hashes.
    public static final int SALT_BYTE_SIZE = 24;
    public static final int HASH_BYTE_SIZE = 18;

    // These constants define the encoding and may not be changed.
    private static final int HASH_SECTIONS = 6;
    private static final int HASH_ALGORITHM_INDEX = 0;
    private static final int ITERATION_INDEX = 1;
    private static final int HASH_SIZE_INDEX = 2;
    private static final int PEPPER_INDEX = 3;
    private static final int SALT_INDEX = 4;
    private static final int HASH_INDEX = 5;

    /**
     * Generates a secure random salt of 24 bytes.
     * 
     * @return byte array salt
     */
    public static byte[] randomSalt() {
        return randomSalt(SALT_BYTE_SIZE);
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
     * Creates a Hash from the given string using PBKDF2 SHA1. Use this to create new user's
     * passwords. Or when they change their password.
     * 
     * @param password
     *            - The password to be salted and hashed.
     * @return A hash String
     * @throws BadOperationException
     * @throws NoSuchAlgorithmException
     *             if algorithm is not supported
     * @see https://en.wikipedia.org/wiki/Hash_function
     */
    public static String create(String password)
            throws BadOperationException, NoSuchAlgorithmException {
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
     *             if one or more parameters are invalid
     * @throws NoSuchAlgorithmException
     *             if algorithm is not supported
     * @see https://en.wikipedia.org/wiki/Hash_function
     */
    public static String create(char[] password)
            throws BadOperationException, NoSuchAlgorithmException {
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
     *             if one or more parameters are invalid
     * @throws NoSuchAlgorithmException
     *             if algorithm is not supported
     * @see https://en.wikipedia.org/wiki/Hash_function
     */
    public static String create(String password, String algorithm)
            throws BadOperationException, NoSuchAlgorithmException {
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
     *             if one or more parameters are invalid
     * @throws NoSuchAlgorithmException
     *             if algorithm is not supported
     * @see https://en.wikipedia.org/wiki/Hash_function
     */
    public static String create(char[] password, String algorithm)
            throws BadOperationException, NoSuchAlgorithmException {
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
     *             if one or more parameters are invalid
     * @throws NoSuchAlgorithmException
     *             if algorithm is not supported
     * @see https://en.wikipedia.org/wiki/Hash_function
     */
    public static String create(String password, String pepper, String algorithm)
            throws BadOperationException, NoSuchAlgorithmException {
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
     *            - Expects an algorithm like Hash.PBKDF2_HMACSHA512 or Hash.BCRYPT
     * @return A hash String
     * @throws BadOperationException
     *             if one or more parameters are invalid
     * @throws NoSuchAlgorithmException
     *             if algorithm is not supported
     * @see https://en.wikipedia.org/wiki/Hash_function
     */
    public static String create(char[] password, char[] pepper, String algorithm)
            throws BadOperationException, NoSuchAlgorithmException {
        // Generate a random salt
        byte[] salt = randomSalt();

        // add pepper if not empty
        char isPeppered = 'n';
        String pepperPassword = new String(password);
        if (pepper != null && pepper.length > 0) {
            isPeppered = 'y';
            pepperPassword = (new String(pepper) + pepperPassword);
        }

        if (algorithm.startsWith("PBKDF2")) {
            // Hash the password
            byte[] hash = PBKDF2.create(pepperPassword.toCharArray(), salt, algorithm,
                    PBKDF2.ITERATIONS, HASH_BYTE_SIZE);

            // format for storage
            String parts = PBKDF2.ITERATIONS + ":" + hash.length + ":" + isPeppered + ":"
                    + encodeBase64(salt) + ":" + encodeBase64(hash);

            if (algorithm.equals(PBKDF2_HMACSHA1)) {
                parts = "pbkdf2sha1:" + parts;
            } else if (algorithm.equals(PBKDF2_HMACSHA256)) {
                parts = "pbkdf2sha256:" + parts;
            } else if (algorithm.equals(PBKDF2_HMACSHA512)) {
                parts = "pbkdf2sha512:" + parts;
            }

            return parts;
        } else if (algorithm.equalsIgnoreCase(BCRYPT)) {
            // Hash the password
            String hash = BCrypt.create(pepperPassword);

            // format for storage
            String parts = BCRYPT + ":" + BCrypt.LOG2_ROUNDS + ":" + hash.length() + ":"
                    + isPeppered + "::" + hash;

            return parts;
        } else if (algorithm.equalsIgnoreCase(SCRYPT)) {
            // Hash the password
            String hash = SCrypt.create(pepperPassword);

            // format for storage
            String parts = SCRYPT + ":" + SCrypt.COST + ":" + hash.length() + ":"
                    + isPeppered + "::" + hash;

            return parts;
        } else {
            // unrecognized algorithm
            throw new BadOperationException("Unsupported algorithm type.");
        }
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
     *             if one or more parameters are invalid
     * @throws InvalidHashException
     *             if the correctHash was missing parts or invalid
     * @throws NoSuchAlgorithmException
     *             if algorithm is not supported
     * @see https://en.wikipedia.org/wiki/Hash_function
     */
    public static boolean verify(String password, String correctHash)
            throws BadOperationException, InvalidHashException, NoSuchAlgorithmException {
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
     *             if one or more parameters are invalid
     * @throws InvalidHashException
     *             if the correctHash was missing parts or invalid
     * @throws NoSuchAlgorithmException
     *             if algorithm is not supported
     * @see https://en.wikipedia.org/wiki/Hash_function
     */
    public static boolean verify(char[] password, String correctHash)
            throws BadOperationException, InvalidHashException, NoSuchAlgorithmException {
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
     *             if one or more parameters are invalid
     * @throws InvalidHashException
     *             if the correctHash was missing parts or invalid
     * @throws NoSuchAlgorithmException
     *             if algorithm is not supported
     * @see https://en.wikipedia.org/wiki/Hash_function
     */
    public static boolean verify(String password, String pepper, String correctHash)
            throws BadOperationException, InvalidHashException, NoSuchAlgorithmException {
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
     *             if one or more parameters are invalid
     * @throws InvalidHashException
     *             if the correctHash was missing parts or invalid
     * @throws NoSuchAlgorithmException
     *             if algorithm is not supported
     * @see https://en.wikipedia.org/wiki/Hash_function
     */
    public static boolean verify(char[] password, char[] pepper, String correctHash)
            throws NoSuchAlgorithmException, InvalidHashException, BadOperationException {
        // Decode the hash into its parameters
        String[] params = correctHash.split(":");
        if (params.length != HASH_SECTIONS) {
            throw new InvalidHashException("Fields are missing from the correct hash.");
        }

        // validate parts
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

        int storedHashSize = 0;
        try {
            storedHashSize = Integer.parseInt(params[HASH_SIZE_INDEX]);
        } catch (NumberFormatException ex) {
            throw new InvalidHashException("Could not parse the hash size as an integer.", ex);
        }

        // verify algorithm
        String algorithm = params[HASH_ALGORITHM_INDEX];
        if (algorithm.toLowerCase().startsWith("pbkdf2")) {

            if (algorithm.equals("pbkdf2sha1")) {
                algorithm = PBKDF2_HMACSHA1;
            } else if (algorithm.equals("pbkdf2sha256")) {
                algorithm = PBKDF2_HMACSHA256;
            } else if (algorithm.equals("pbkdf2sha512")) {
                algorithm = PBKDF2_HMACSHA512;
            }

            byte[] hash = null;
            try {
                hash = decodeBase64(params[HASH_INDEX]);
            } catch (IllegalArgumentException ex) {
                throw new InvalidHashException("Base64 decoding of hash failed.", ex);
            }

            if (storedHashSize != hash.length) {
                throw new InvalidHashException("Hash length doesn't match stored hash length.");
            }

            // Compute the hash of the provided string, using the same salt,
            // iteration count, and hash length
            byte[] testHash = PBKDF2.create(pepperPassword.toCharArray(), salt, algorithm,
                    iterations, hash.length);

            // Compare the hashes in constant time.
            return slowEquals(hash, testHash);
        } else if (algorithm.equals(BCRYPT)) {

            byte[] hash = null;
            try {
                hash = params[HASH_INDEX].getBytes();
            } catch (Exception ex) {
                throw new InvalidHashException("Parsing of hash failed.", ex);
            }

            if (storedHashSize != hash.length) {
                throw new InvalidHashException("Hash length doesn't match stored hash length.");
            }

            byte[] testHash = BCrypt.create(pepperPassword, new String(hash), iterations).getBytes();

            // Compare the hashes in constant time.
            return slowEquals(hash, testHash);
        } else if (algorithm.equals(SCRYPT)) {

            byte[] hash = null;
            try {
                hash = params[HASH_INDEX].getBytes();
            } catch (Exception ex) {
                throw new InvalidHashException("Parsing of hash failed.", ex);
            }

            if (storedHashSize != hash.length) {
                throw new InvalidHashException("Hash length doesn't match stored hash length.");
            }

            return SCrypt.verify(pepperPassword, new String(hash));
        } else {
            // unrecognized algorithm
            throw new NoSuchAlgorithmException("Unsupported algorithm type.");
        }
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
    protected static boolean slowEquals(byte[] byteA, byte[] byteB) {
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
    protected static byte[] decodeBase64(String string) {
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
    protected static String encodeBase64(byte[] array) {
        return new String(Base64.getEncoder().encode(array));
    }

}
