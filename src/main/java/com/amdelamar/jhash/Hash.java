package com.amdelamar.jhash;

import com.amdelamar.jhash.algorithms.BCrypt;
import com.amdelamar.jhash.algorithms.PBKDF2;
import com.amdelamar.jhash.algorithms.SCrypt;
import com.amdelamar.jhash.algorithms.Type;
import com.amdelamar.jhash.exception.InvalidHashException;
import com.amdelamar.jhash.util.Base64Decoder;
import com.amdelamar.jhash.util.Base64Encoder;
import com.amdelamar.jhash.util.HashUtils;

/**
 * Password hashing utility in Java. It salts automatically and has a pepper option. It hashes
 * passwords with PBKDF2 using 64,000 iterations of SHA1 (default), SHA256, or SHA512. Follows
 * the builder pattern, so start with Hash.password(pw).create() and use .verify(hash) to
 * check if valid password hash matches.
 *
 * @author amdelamar
 * @version 2.2.0
 * @see <a href="https://github.com/amdelamar/jhash">https://github.com/amdelamar/jhash</a>
 * @see <a href="https://en.wikipedia.org/wiki/Hash_function">https://en.wikipedia.org/wiki/Hash_function</a>
 * @since 1.0.0
 */
public class Hash {

    // These constants define the encoding and may not be changed.
    private static final String SCRYPT = "scrypt";
    private static final String BCRYPT = "bcrypt";
    private static final String PBKDF2_HMACSHA1 = "PBKDF2WithHmacSHA1";
    private static final String PBKDF2_HMACSHA256 = "PBKDF2WithHmacSHA256";
    private static final String PBKDF2_HMACSHA512 = "PBKDF2WithHmacSHA512";
    private static final String HASH_LENGTH_MISMATCH = "Hash length doesn't match stored hash length.";
    private static final int HASH_SECTIONS = 7;
    private static final int HASH_ALGORITHM_INDEX = 0;
    private static final int ITERATION_INDEX = 1;
    private static final int HASH_SIZE_INDEX = 2;
    private static final int SALT_SIZE_INDEX = 3;
    private static final int PEPPER_INDEX = 4;
    private static final int SALT_INDEX = 5;
    private static final int HASH_INDEX = 6;

    // Hash parameters with defaults
    private char[] password;
    private char[] pepper;
    private int hashLength = 0;
    private int saltLength = 0;
    private int factor = 0;
    private Type algorithm = Type.PBKDF2_SHA1;
    private Base64Decoder decoder = HashUtils.defaultBase64Decoder;
    private Base64Encoder encoder = HashUtils.defaultBase64Encoder;

    /**
     * The password to be hashed. Note: Call create() when ready to output the hash value.
     * You can also specify optional parameters such as pepper, factor, algorithm, and more.
     * But this has to be done before you call create().
     *
     * @param password char[]
     * @return Hash
     * @throws IllegalArgumentException if password is null or empty
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
     * Optional value for the application-specific <a href="https://en.wikipedia.org/wiki/Pepper_(cryptography)">pepper</a>.
     *
     * @param pepper char[]
     * @return Hash
     * @see <a href="https://en.wikipedia.org/wiki/Pepper_(cryptography)">https://en.wikipedia.org/wiki/Pepper_(cryptography)</a>
     */
    public Hash pepper(char[] pepper) {
        this.pepper = pepper;
        return this;
    }

    /**
     * Optional value for hash byte length. Default is 18.
     *
     * @param hashLength int
     * @return Hash
     */
    public Hash hashLength(int hashLength) {
        this.hashLength = hashLength;
        return this;
    }

    /**
     * Optional value for salt byte length. Default is 24.
     *
     * @param saltLength int
     * @return Hash
     */
    public Hash saltLength(int saltLength) {
        this.saltLength = saltLength;
        return this;
    }

    /**
     * Optional value for selecting hash algorithm. E.g. Type.PBKDF2_SHA512, Type.BCRYPT,
     * or Type.SCRYPT.
     * Default is Type.PBKDF2_SHA1
     *
     * @param algorithm Type
     * @return Hash
     */
    public Hash algorithm(Type algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    /**
     * Optional value for iterations (PBKDF2), logrounds (BCRYPT), or cost (SCRYPT). Set to 0
     * if you're unsure and it will use the default value for the specified algorithm.
     *
     * @param factor int
     * @return Hash
     */
    public Hash factor(int factor) {
        this.factor = factor;
        return this;
    }

    /**
     * Optional value for Base64 encoder implementation.
     * Default is {@link org.apache.commons.codec.binary.Base64#encode(byte[])}
     *
     * @param encoder HashUtils.Base64Encoder
     * @return Hash
     */
    public Hash encoder(Base64Encoder encoder) {
        this.encoder = encoder;
        return this;
    }

    /**
     * Optional value for Base64 decoder implementation.
     * Default is {@link org.apache.commons.codec.binary.Base64#decode(String)}
     *
     * @param decoder HashUtils.Base64Decoder
     * @return Hash
     */
    public Hash decoder(Base64Decoder decoder) {
        this.decoder = decoder;
        return this;
    }

    /**
     * Creates a Hash from the given char array using the specified algorithm. Use this to
     * create new user's passwords. Or when they change their password.
     *
     * @return String hash
     * @throws IllegalArgumentException if one or more parameters are invalid
     * @see <a href="https://en.wikipedia.org/wiki/Hash_function">https://en.wikipedia.org/wiki/Hash_function</a>
     */
    public String create() throws IllegalArgumentException {

        // add pepper if not empty
        char isPeppered = 'n';
        String pepperPassword = new String(password);
        if (pepper != null && pepper.length > 0) {
            isPeppered = 'y';
            pepperPassword = (new String(pepper) + pepperPassword);
        }

        if (algorithm == Type.PBKDF2_SHA1 || algorithm == Type.PBKDF2_SHA256 || algorithm == Type.PBKDF2_SHA512) {

            String alg = null;
            String alg2 = null;
            if (algorithm == Type.PBKDF2_SHA1) {
                alg = Hash.PBKDF2_HMACSHA1;
                alg2 = "pbkdf2sha1";
            } else if (algorithm == Type.PBKDF2_SHA256) {
                alg = Hash.PBKDF2_HMACSHA256;
                alg2 = "pbkdf2sha256";
            } else {
                alg = Hash.PBKDF2_HMACSHA512;
                alg2 = "pbkdf2sha512";
            }

            if (hashLength <= 0) {
                // default hash length
                hashLength = PBKDF2.DEFAULT_HASH_LENGTH;
            }

            if (saltLength <= 0) {
                // default salt length
                saltLength = PBKDF2.DEFAULT_SALT_LENGTH;
            }

            if (factor <= 0) {
                // default factor
                factor = PBKDF2.DEFAULT_ITERATIONS;
            }

            // Generate a random salt
            byte[] salt = HashUtils.randomSalt(saltLength);

            // Hash the password
            byte[] hash = PBKDF2.create(pepperPassword.toCharArray(), salt, alg, factor, hashLength);

            // format for storage
            StringBuilder finalHash = new StringBuilder(alg2).append(":")
                    .append(factor)
                    .append(":")
                    .append(hash.length)
                    .append(":")
                    .append(salt.length)
                    .append(":")
                    .append(isPeppered)
                    .append(":")
                    .append(encoder.encode(salt))
                    .append(":")
                    .append(encoder.encode(hash));

            return finalHash.toString();

        } else if (algorithm == Type.BCRYPT) {

            if (factor <= 0) {
                // default factor
                factor = BCrypt.DEFAULT_LOG2_ROUNDS;
            }

            if (saltLength <= 0) {
                // default salt length
                saltLength = BCrypt.DEFAULT_SALT_LENGTH;
            }

            // Hash the password
            String hash = BCrypt.create(pepperPassword, null, saltLength, factor);

            // format for storage
            StringBuilder finalHash = new StringBuilder(BCRYPT).append(":")
                    .append(factor)
                    .append(":")
                    .append(hash.length())
                    .append(":")
                    .append(saltLength)
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

            if (saltLength <= 0) {
                // default salt length
                saltLength = SCrypt.DEFAULT_SALT_LENGTH;
            }

            // Hash the password
            String hash = SCrypt.create(pepperPassword, saltLength, factor, encoder);

            // format for storage
            StringBuilder finalHash = new StringBuilder(SCRYPT).append(":")
                    .append(factor)
                    .append(":")
                    .append(hash.length())
                    .append(":")
                    .append(saltLength)
                    .append(":")
                    .append(isPeppered)
                    .append("::")
                    .append(hash);

            return finalHash.toString();

        } else {
            // unrecognized algorithm
            throw new IllegalArgumentException("Unsupported algorithm type. Expected Type.BCRYPT, Type.SCRIPT, or other Type enum.");
        }
    }

    /**
     * Returns true if the password (and pepper) to be hashed matches the expected correctHash.
     * Use this to verify a user login. Note: you must provide a pepper before calling this method
     * if you used a pepper to hash the correctHash from before.
     *
     * @param correctHash The string hash from storage.
     * @return boolean true if matches
     * @throws InvalidHashException if the correctHash was missing parts or invalid
     * @see <a href="https://en.wikipedia.org/wiki/Hash_function">https://en.wikipedia.org/wiki/Hash_function</a>
     */
    public boolean verify(String correctHash) throws InvalidHashException {
        // check hash
        if (correctHash == null || correctHash.isEmpty()) {
            throw new InvalidHashException("Correct hash cannot be null or empty.");
        }

        // Decode the hash into its parameters
        String[] params = correctHash.split(":");
        if (params.length != HASH_SECTIONS) {
            throw new InvalidHashException("Fields are missing from the correct hash. Double-check JHash vesrion and hash format.");
        }

        // validate each part
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
        if ('y' == params[PEPPER_INDEX].charAt(0)) {
            pepperPassword = (new String(pepper) + pepperPassword);
        }

        byte[] salt = decoder.decode(params[SALT_INDEX]);

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

        // verify algorithm
        String algorithm = params[HASH_ALGORITHM_INDEX];
        if (algorithm.toLowerCase()
                .startsWith("pbkdf2")) {

            if ("pbkdf2sha1".equals(algorithm)) {
                algorithm = PBKDF2_HMACSHA1;
            } else if ("pbkdf2sha256".equals(algorithm)) {
                algorithm = PBKDF2_HMACSHA256;
            } else if ("pbkdf2sha512".equals(algorithm)) {
                algorithm = PBKDF2_HMACSHA512;
            }

            byte[] hash = decoder.decode(params[HASH_INDEX]);

            if (storedHashSize != hash.length) {
                throw new InvalidHashException(HASH_LENGTH_MISMATCH);
            }

            // Compute the hash of the provided string, using the same salt,
            // iteration count, and hash length
            byte[] testHash = PBKDF2.create(pepperPassword.toCharArray(), salt, algorithm, iterations, hash.length);

            // Compare the hashes in constant time.
            return HashUtils.slowEquals(hash, testHash);

        } else if (algorithm.equals(BCRYPT)) {

            byte[] hash = params[HASH_INDEX].getBytes();

            if (storedHashSize != hash.length) {
                throw new InvalidHashException(HASH_LENGTH_MISMATCH);
            }

            byte[] testHash = BCrypt.create(pepperPassword, new String(hash), storedSaltSize, iterations)
                    .getBytes();

            // Compare the hashes in constant time.
            return HashUtils.slowEquals(hash, testHash);

        } else if (algorithm.equals(SCRYPT)) {

            byte[] hash = params[HASH_INDEX].getBytes();

            if (storedHashSize != hash.length) {
                throw new InvalidHashException(HASH_LENGTH_MISMATCH);
            }

            return SCrypt.verify(pepperPassword, new String(hash));

        } else {
            // unrecognized algorithm
            throw new InvalidHashException("Unsupported algorithm type: " + algorithm);
        }
    }

}
