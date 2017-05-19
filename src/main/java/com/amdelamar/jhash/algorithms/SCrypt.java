package com.amdelamar.jhash.algorithms;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.amdelamar.jhash.util.HashUtils;

/**
 * SCrypt implements the password-based key derivative function created by Colin Percival. It
 * follows the scrypt algorithm published by IETF (RFC 7914).
 * 
 * @author amdelamar, Will Glozer
 * @see https://en.wikipedia.org/wiki/Scrypt
 */
public class SCrypt {

    public static final int COST = 131072;
    public static final int BLOCKSIZE = 8;
    public static final int PARALLEL = 1;

    private static int log2(int num) {
        int log = 0;
        if ((num & 0xffff0000) != 0) {
            num >>>= 16;
            log = 16;
        }
        if (num >= 256) {
            num >>>= 8;
            log += 8;
        }
        if (num >= 16) {
            num >>>= 4;
            log += 4;
        }
        if (num >= 4) {
            num >>>= 2;
            log += 2;
        }
        return log + (num >>> 1);
    }

    /**
     * Pure Java implementation of the <a href="http://www.tarsnap.com/scrypt/scrypt.pdf"/>scrypt
     * KDF</a>.
     *
     * @param password
     *            Password.
     * @param salt
     *            Salt.
     * @param cost
     *            Overall CPU/MEM cost parameter. 2^15 for testing, but 2^20 recommended.
     * @param blockSize
     *            Block size for each mixing loop (memory usage).
     * @param parallel
     *            Parallelization to control the number of independent mixing loops.
     * @param length
     *            Intended length of the derived key.
     *
     * @return The derived key.
     *
     * @throws NoSuchAlgorithmException
     *             when HMAC_SHA256 is not available.
     * @throws IllegalArgumentException
     *             when parameters invalid
     */
    private static byte[] scrypt(byte[] password, byte[] salt, int cost, int blocksize,
            int parallel, int length) throws GeneralSecurityException {
        if (cost < 2 || (cost & (cost - 1)) != 0)
            throw new IllegalArgumentException("Cost must be a power of 2 greater than 1");

        if (cost > Integer.MAX_VALUE / 128 / blocksize)
            throw new IllegalArgumentException("Parameter cost is too large");
        if (blocksize > Integer.MAX_VALUE / 128 / parallel)
            throw new IllegalArgumentException("Parameter blocksize is too large");

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(password, "HmacSHA256"));

        byte[] key = new byte[length];

        byte[] b1 = new byte[128 * blocksize * parallel];
        byte[] xy = new byte[256 * blocksize];
        byte[] v1 = new byte[128 * blocksize * cost];

        pbkdf2(mac, salt, 1, b1, parallel * 128 * blocksize);

        for (int i = 0; i < parallel; i++) {
            smix(b1, i * 128 * blocksize, blocksize, cost, v1, xy);
        }

        pbkdf2(mac, b1, 1, key, length);

        return key;
    }

    private static void smix(byte[] b1, int bi, int round, int cpu, byte[] v1, byte[] xy) {
        int xi = 0;
        int yi = 128 * round;

        System.arraycopy(b1, bi, xy, xi, 128 * round);

        for (int i = 0; i < cpu; i++) {
            System.arraycopy(xy, xi, v1, i * (128 * round), 128 * round);
            blockmix_salsa8(xy, xi, yi, round);
        }

        for (int i = 0; i < cpu; i++) {
            int j = integerify(xy, xi, round) & (cpu - 1);
            blockxor(v1, j * (128 * round), xy, xi, 128 * round);
            blockmix_salsa8(xy, xi, yi, round);
        }

        System.arraycopy(xy, xi, b1, bi, 128 * round);
    }

    private static void blockmix_salsa8(byte[] by, int bi, int yi, int round) {

        byte[] x1 = new byte[64];
        System.arraycopy(by, bi + (2 * round - 1) * 64, x1, 0, 64);

        for (int i = 0; i < 2 * round; i++) {
            blockxor(by, i * 64, x1, 0, 64);
            salsa(x1);
            System.arraycopy(x1, 0, by, yi + (i * 64), 64);
        }

        for (int i = 0; i < round; i++) {
            System.arraycopy(by, yi + (i * 2) * 64, by, bi + (i * 64), 64);
        }

        for (int i = 0; i < round; i++) {
            System.arraycopy(by, yi + (i * 2 + 1) * 64, by, bi + (i + round) * 64, 64);
        }
    }

    private static int r1(int left, int right) {
        return (left << right) | (left >>> (32 - right));
    }

    private static void salsa(byte[] b1) {

        int[] base32 = new int[16];
        for (int i = 0; i < 16; i++) {
            base32[i] = (b1[i * 4 + 0] & 0xff) << 0;
            base32[i] |= (b1[i * 4 + 1] & 0xff) << 8;
            base32[i] |= (b1[i * 4 + 2] & 0xff) << 16;
            base32[i] |= (b1[i * 4 + 3] & 0xff) << 24;
        }

        int[] x1 = new int[16];
        System.arraycopy(base32, 0, x1, 0, 16);

        for (int i = 8; i > 0; i -= 2) {
            x1[4] ^= r1(x1[0] + x1[12], 7);
            x1[8] ^= r1(x1[4] + x1[0], 9);
            x1[12] ^= r1(x1[8] + x1[4], 13);
            x1[0] ^= r1(x1[12] + x1[8], 18);
            x1[9] ^= r1(x1[5] + x1[1], 7);
            x1[13] ^= r1(x1[9] + x1[5], 9);
            x1[1] ^= r1(x1[13] + x1[9], 13);
            x1[5] ^= r1(x1[1] + x1[13], 18);
            x1[14] ^= r1(x1[10] + x1[6], 7);
            x1[2] ^= r1(x1[14] + x1[10], 9);
            x1[6] ^= r1(x1[2] + x1[14], 13);
            x1[10] ^= r1(x1[6] + x1[2], 18);
            x1[3] ^= r1(x1[15] + x1[11], 7);
            x1[7] ^= r1(x1[3] + x1[15], 9);
            x1[11] ^= r1(x1[7] + x1[3], 13);
            x1[15] ^= r1(x1[11] + x1[7], 18);
            x1[1] ^= r1(x1[0] + x1[3], 7);
            x1[2] ^= r1(x1[1] + x1[0], 9);
            x1[3] ^= r1(x1[2] + x1[1], 13);
            x1[0] ^= r1(x1[3] + x1[2], 18);
            x1[6] ^= r1(x1[5] + x1[4], 7);
            x1[7] ^= r1(x1[6] + x1[5], 9);
            x1[4] ^= r1(x1[7] + x1[6], 13);
            x1[5] ^= r1(x1[4] + x1[7], 18);
            x1[11] ^= r1(x1[10] + x1[9], 7);
            x1[8] ^= r1(x1[11] + x1[10], 9);
            x1[9] ^= r1(x1[8] + x1[11], 13);
            x1[10] ^= r1(x1[9] + x1[8], 18);
            x1[12] ^= r1(x1[15] + x1[14], 7);
            x1[13] ^= r1(x1[12] + x1[15], 9);
            x1[14] ^= r1(x1[13] + x1[12], 13);
            x1[15] ^= r1(x1[14] + x1[13], 18);
        }

        for (int i = 0; i < 16; ++i) {
            base32[i] = x1[i] + base32[i];
        }

        for (int i = 0; i < 16; i++) {
            b1[i * 4 + 0] = (byte) (base32[i] >> 0 & 0xff);
            b1[i * 4 + 1] = (byte) (base32[i] >> 8 & 0xff);
            b1[i * 4 + 2] = (byte) (base32[i] >> 16 & 0xff);
            b1[i * 4 + 3] = (byte) (base32[i] >> 24 & 0xff);
        }
    }

    private static void blockxor(byte[] s1, int si, byte[] d1, int di, int length) {
        for (int i = 0; i < length; i++) {
            d1[di + i] ^= s1[si + i];
        }
    }

    private static int integerify(byte[] b1, int bi, int round) {

        bi += (2 * round - 1) * 64;

        int n = (b1[bi + 0] & 0xff) << 0;
        n |= (b1[bi + 1] & 0xff) << 8;
        n |= (b1[bi + 2] & 0xff) << 16;
        n |= (b1[bi + 3] & 0xff) << 24;

        return n;
    }

    /**
     * Implementation of PBKDF2 (RFC2898).
     *
     * @param mac
     *            Pre-initialized {@link Mac} instance to use.
     * @param salt
     *            Salt.
     * @param iterations
     *            Iteration count.
     * @param key
     *            Byte array that derived key will be placed in.
     * @param length
     *            Intended length, in octets, of the derived key.
     *
     * @throws GeneralSecurityException
     *             If key length is too long
     */
    private static void pbkdf2(Mac mac, byte[] salt, int iterations, byte[] key, int length)
            throws GeneralSecurityException {
        int len = mac.getMacLength();

        if (length > (Math.pow(2, 32) - 1) * len) {
            throw new GeneralSecurityException("Requested key length too long");
        }

        byte[] u1 = new byte[len];
        byte[] t1 = new byte[len];
        byte[] block = new byte[salt.length + 4];

        int limit = (int) Math.ceil((double) length / len);
        int r = length - (limit - 1) * len;

        System.arraycopy(salt, 0, block, 0, salt.length);

        for (int i = 1; i <= limit; i++) {
            block[salt.length + 0] = (byte) (i >> 24 & 0xff);
            block[salt.length + 1] = (byte) (i >> 16 & 0xff);
            block[salt.length + 2] = (byte) (i >> 8 & 0xff);
            block[salt.length + 3] = (byte) (i >> 0 & 0xff);

            mac.update(block);
            mac.doFinal(u1, 0);
            System.arraycopy(u1, 0, t1, 0, len);

            for (int j = 1; j < iterations; j++) {
                mac.update(u1);
                mac.doFinal(u1, 0);

                for (int k = 0; k < len; k++) {
                    t1[k] ^= u1[k];
                }
            }

            System.arraycopy(t1, 0, key, (i - 1) * len, (i == limit ? r : len));
        }
    }

    /**
     * Compare the supplied plaintext password to a hashed password.
     *
     * @param password
     *            Plaintext password.
     * @param hashed
     *            scrypt hashed password.
     *
     * @return true if password matches hashed value.
     * @throws IllegalStateException
     *             If JVM doesn't support necessary functions.
     */
    public static boolean verify(String password, String hashed) throws IllegalStateException {
        try {
            String[] parts = hashed.split("\\$");

            if (parts.length != 5 || !parts[1].equals("s0")) {
                throw new IllegalArgumentException("Invalid hashed value");
            }

            long params = Long.parseLong(parts[2], 16);
            byte[] salt = HashUtils.decodeBase64(parts[3]);
            byte[] derived0 = HashUtils.decodeBase64(parts[4]);

            int N = (int) Math.pow(2, params >> 16 & 0xffff);
            int r = (int) params >> 8 & 0xff;
            int p = (int) params & 0xff;

            byte[] derived1 = SCrypt.scrypt(password.getBytes("UTF-8"), salt, N, r, p, 32);

            if (derived0.length != derived1.length)
                return false;

            int result = 0;
            for (int i = 0; i < derived0.length; i++) {
                result |= derived0[i] ^ derived1[i];
            }
            return result == 0;
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("JVM doesn't support UTF-8?");
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("JVM doesn't support SHA1PRNG or HMAC_SHA256?");
        }
    }

    /**
     * Hash the supplied plaintext password and generate output in the format described in
     * {@link SCryptUtil}.
     *
     * @param password
     *            Password. *
     * @return The hashed password.
     * @throws IllegalStateException
     *             If JVM doesn't support necessary functions.
     */
    public static String create(String password) throws IllegalStateException {
        return create(password, COST, BLOCKSIZE, PARALLEL);
    }

    /**
     * Hash the supplied plaintext password and generate output in the format described in
     * {@link SCryptUtil}.
     *
     * @param password
     *            Password.
     * @param cost
     *            Overall CPU/MEM cost parameter. 2^15 for testing, but 2^20 recommended.
     * @param blockSize
     *            Block size for each mixing loop (memory usage)
     * @param parallel
     *            Parallelization to control the number of independent mixing loops.
     *
     * @return The hashed password.
     * @throws IllegalStateException
     *             If JVM doesn't support necessary functions.
     */
    public static String create(String password, int cost, int blockSize, int parallel)
            throws IllegalStateException {
        try {
            byte[] salt = HashUtils.randomSalt(16);

            byte[] derived = scrypt(password.getBytes("UTF-8"), salt, cost, blockSize, parallel,
                    32);

            String params = Long.toString(log2(cost) << 16L | blockSize << 8 | parallel, 16);

            StringBuilder sb = new StringBuilder((salt.length + derived.length) * 2);
            sb.append("$s0$").append(params).append('$');
            sb.append(HashUtils.encodeBase64(salt)).append('$');
            sb.append(HashUtils.encodeBase64(derived));

            return sb.toString();
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("JVM doesn't support UTF-8?");
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("JVM doesn't support SHA1PRNG or HMAC_SHA256?");
        }
    }
}
