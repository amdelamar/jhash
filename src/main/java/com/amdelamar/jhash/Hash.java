package com.amdelamar.jhash;

import java.security.NoSuchAlgorithmException;

import com.amdelamar.jhash.algorithms.BCrypt;
import com.amdelamar.jhash.algorithms.PBKDF2;
import com.amdelamar.jhash.algorithms.SCrypt;
import com.amdelamar.jhash.algorithms.Type;
import com.amdelamar.jhash.exception.BadOperationException;
import com.amdelamar.jhash.exception.InvalidHashException;
import com.amdelamar.jhash.util.HashUtils;

/**
 * Password hashing utility in Java. It salts automatically and has a pepper option. It hashes
 * passwords with PBKDF2 using 64,000 iterations of SHA1 (default), SHA256, or SHA512. Follows
 * the builder pattern, so start with Hash.password(pw).create() and use .verify(hash) to
 * check if valid password hash matches.
 * 
 * @author amdelamar
 * @version 2.0.0
 * @see https://github.com/amdelamar/jhash
 */
public class Hash {

    /**
     * Default hash byte length
     */
    public static final int DEFAULT_HASH_BYTE_SIZE = 18;

    /**
     * Default salt byte length
     */
    public static final int DEFAULT_SALT_BYTE_SIZE = 24;

    /**
     * Default algorithm type
     */
    public static final Type DEFAULT_ALGORITHM = Type.PBKDF2_SHA1;

    /**
     * Default factor
     */
    public static final int DEFAULT_FACTOR = 0;

    // These constants define the encoding and may not be changed.
    private static final String SCRYPT = "scrypt";
    private static final String BCRYPT = "bcrypt";
    private static final String PBKDF2_HMACSHA1 = "PBKDF2WithHmacSHA1";
    private static final String PBKDF2_HMACSHA256 = "PBKDF2WithHmacSHA256";
    private static final String PBKDF2_HMACSHA512 = "PBKDF2WithHmacSHA512";
    private static final int HASH_SECTIONS = 7;
    private static final int HASH_ALGORITHM_INDEX = 0;
    private static final int ITERATION_INDEX = 1;
    private static final int HASH_SIZE_INDEX = 2;
    private static final int SALT_SIZE_INDEX = 3;
    private static final int PEPPER_INDEX = 4;
    private static final int SALT_INDEX = 5;
    private static final int HASH_INDEX = 6;

    // Hash parameters
    private char[] password;
    private char[] pepper;
    private int hashLength = DEFAULT_HASH_BYTE_SIZE;
    private int saltLength = DEFAULT_SALT_BYTE_SIZE;
    private int factor = DEFAULT_FACTOR;
    private Type algorithm = DEFAULT_ALGORITHM;

    /**
     * The password to be hashed. Note: Call create() when ready to output the hash value. 
     * You can also specify optional parameters such as pepper, factor, algorithm, and more. 
     * But this has to be done before you call create().
     * @param char[] password
     * @return Hash
     */
    public static Hash password(char[] password) {
        if (password == null || password.length < 1) {
            throw new IllegalArgumentException("Password cannot be null or empty.");
        }
        Hash hash = new Hash();
        hash.password = password;
        return hash;
    }

    /**
     * Optional value for the application-specific pepper.
     * @param char[] pepper
     * @return Hash
     * @see https://en.wikipedia.org/wiki/Pepper_(cryptography)
     */
    public Hash pepper(char[] pepper) {
        if (pepper == null || pepper.length < 1) {
            throw new IllegalArgumentException("Pepper cannot be null or empty.");
        }
        this.pepper = pepper;
        return this;
    }

    /**
     * Optional value for hash byte length. Default is 18.
     * @param int hashLength
     * @return Hash
     */
    public Hash hashLength(int hashLength) {
        this.hashLength = hashLength;
        return this;
    }

    /**
     * Optional value for salt byte length. Default is 24.
     * @param saltLength
     * @return
     */
    public Hash saltLength(int saltLength) {
        this.saltLength = saltLength;
        return this;
    }

    /**
     * Optional value for selecting hash algorithm. E.g. Type.PBKDF2_SHA512, Type.BCRYPT, 
     * or Type.SCRYPT.
     * Default is Type.PBKDF2_SHA1
     * @param Type algorithm
     * @return Hash
     */
    public Hash algorithm(Type algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    /**
     * Optional value for iterations (PBKDF2), logrounds (BCRYPT), or cost (SCRYPT). Set to 0 
     * if you're unsure and it will use the default value for the specified algorithm.
     * @param int factor
     * @return Hash
     */
    public Hash factor(int factor) {
        this.factor = factor;
        return this;
    }

    /**
     * Creates a Hash from the given char array using the specified algorithm. Use this to 
     * create new user's passwords. Or when they change their password.
     * @return A String hash
     * @throws BadOperationException
     *             if one or more parameters are invalid
     * @throws NoSuchAlgorithmException
     *             if algorithm is not supported
     * @see https://en.wikipedia.org/wiki/Hash_function
     */
    public String create() throws BadOperationException, NoSuchAlgorithmException {
        // Generate a random salt
        byte[] salt = HashUtils.randomSalt(saltLength);

        // add pepper if not empty
        char isPeppered = 'n';
        String pepperPassword = new String(password);
        if (pepper != null && pepper.length > 0) {
            isPeppered = 'y';
            pepperPassword = (new String(pepper) + pepperPassword);
        }

        if (algorithm == Type.PBKDF2_SHA1 || algorithm == Type.PBKDF2_SHA256 || algorithm == Type.PBKDF2_SHA512) {

            if (factor <= 0) {
                // default factor
                factor = PBKDF2.ITERATIONS;
            }

            String alg = null;
            if (algorithm == Type.PBKDF2_SHA1) {
                alg = Hash.PBKDF2_HMACSHA1;
            } else if (algorithm == Type.PBKDF2_SHA256) {
                alg = Hash.PBKDF2_HMACSHA256;
            } else if (algorithm == Type.PBKDF2_SHA512) {
                alg = Hash.PBKDF2_HMACSHA512;
            }

            // Hash the password
            byte[] hash = PBKDF2.create(pepperPassword.toCharArray(), salt, alg, factor, hashLength);

            // format for storage
            String alg2 = "pbkdf2sha1";
            if (algorithm == Type.PBKDF2_SHA256) {
                alg2 = "pbkdf2sha256";
            } else if (algorithm == Type.PBKDF2_SHA512) {
                alg2 = "pbkdf2sha512";
            }
            StringBuilder finalHash = new StringBuilder(alg2).append(":")
                    .append(factor)
                    .append(":")
                    .append(hash.length)
                    .append(":")
                    .append(salt.length)
                    .append(":")
                    .append(isPeppered)
                    .append(":")
                    .append(HashUtils.encodeBase64(salt))
                    .append(":")
                    .append(HashUtils.encodeBase64(hash));

            return finalHash.toString();

        } else if (algorithm == Type.BCRYPT) {

            if (factor <= 0) {
                // default factor
                factor = BCrypt.LOG2_ROUNDS;
            }

            // Hash the password
            String hash = BCrypt.create(pepperPassword, factor);

            // format for storage
            StringBuilder finalHash = new StringBuilder(BCRYPT).append(":")
                    .append(factor)
                    .append(":")
                    .append(hash.length())
                    .append(":")
                    .append(salt.length)
                    .append(":")
                    .append(isPeppered)
                    .append("::")
                    .append(hash);

            return finalHash.toString();

        } else if (algorithm == Type.SCRYPT) {

            if (factor <= 0) {
                // default factor
                factor = SCrypt.COST;
            }

            // Hash the password
            String hash = SCrypt.create(pepperPassword, factor);

            // format for storage
            StringBuilder finalHash = new StringBuilder(SCRYPT).append(":")
                    .append(factor)
                    .append(":")
                    .append(hash.length())
                    .append(":")
                    .append(salt.length)
                    .append(":")
                    .append(isPeppered)
                    .append("::")
                    .append(hash);

            return finalHash.toString();

        } else {
            // unrecognized algorithm
            throw new NoSuchAlgorithmException("Unsupported algorithm type. Expected Type.BCRYPT or other.");
        }
    }

    /**
     * Returns true if the password (and pepper) to be hashed matches the expected correctHash. 
     * Use this to verify a user login. Note: you must provide a pepper before calling this method
     * if you used a pepper to hash the correctHash from before.
     * 
     * @param correctHash
     *            The stored hash from storage.
     * @return boolean true if matches
     * @throws BadOperationException
     *             if one or more parameters are invalid
     * @throws InvalidHashException
     *             if the correctHash was missing parts or invalid
     * @throws NoSuchAlgorithmException
     *             if algorithm is not supported
     * @see https://en.wikipedia.org/wiki/Hash_function
     */
    public boolean verify(String correctHash) throws NoSuchAlgorithmException, InvalidHashException, BadOperationException {
        // Decode the hash into its parameters
        String[] params = correctHash.split(":");
        if (params.length != HASH_SECTIONS) {
            throw new InvalidHashException("Fields are missing from the correct hash. Double-check JHash vesrion and hash format.");
        }

        // validate parts
        int iterations = 0;
        try {
            iterations = Integer.parseInt(params[ITERATION_INDEX]);
        } catch (NumberFormatException ex) {
            throw new InvalidHashException("Could not parse the iteration count as an integer.", ex);
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
            salt = HashUtils.decodeBase64(params[SALT_INDEX]);
        } catch (IllegalArgumentException ex) {
            throw new InvalidHashException("Base64 decoding of salt failed.", ex);
        }

        int storedHashSize = 0;
        try {
            storedHashSize = Integer.parseInt(params[HASH_SIZE_INDEX]);
        } catch (NumberFormatException ex) {
            throw new InvalidHashException("Could not parse the hash size as an integer.", ex);
        }

        int storedSaltSize = 0;
        try {
            storedSaltSize = Integer.parseInt(params[SALT_SIZE_INDEX]);
        } catch (NumberFormatException ex) {
            throw new InvalidHashException("Could not parse the salt size as an integer.", ex);
        }

        if (storedSaltSize != saltLength) {
            throw new InvalidHashException("Salt length doesn't match stored salt length.");
        }

        // verify algorithm
        String algorithm = params[HASH_ALGORITHM_INDEX];
        if (algorithm.toLowerCase()
                .startsWith("pbkdf2")) {

            if (algorithm.equals("pbkdf2sha1")) {
                algorithm = PBKDF2_HMACSHA1;
            } else if (algorithm.equals("pbkdf2sha256")) {
                algorithm = PBKDF2_HMACSHA256;
            } else if (algorithm.equals("pbkdf2sha512")) {
                algorithm = PBKDF2_HMACSHA512;
            }

            byte[] hash = null;
            try {
                hash = HashUtils.decodeBase64(params[HASH_INDEX]);
            } catch (IllegalArgumentException ex) {
                throw new InvalidHashException("Base64 decoding of hash failed.", ex);
            }

            if (storedHashSize != hash.length) {
                throw new InvalidHashException("Hash length doesn't match stored hash length.");
            }

            // Compute the hash of the provided string, using the same salt,
            // iteration count, and hash length
            byte[] testHash = PBKDF2.create(pepperPassword.toCharArray(), salt, algorithm, iterations, hash.length);

            // Compare the hashes in constant time.
            return HashUtils.slowEquals(hash, testHash);
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

            byte[] testHash = BCrypt.create(pepperPassword, new String(hash), iterations)
                    .getBytes();

            // Compare the hashes in constant time.
            return HashUtils.slowEquals(hash, testHash);
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

}
