package com.amdelamar.jhash.algorithms;

import com.amdelamar.jhash.Hash;
import com.amdelamar.jhash.exception.InvalidHashException;
import com.amdelamar.jhash.util.HashUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.junit.Assert.*;

@RunWith(JUnit4.class)
public class PBKDF2Tests {

    @Test
    public void constructorTests() {
        PBKDF2 algorithm = new PBKDF2();
        assertNotNull(algorithm);
    }

    @Test
    public void defaultTests() throws InvalidHashException {

        char[] pepper = "ZfMifTCEvjyDGIqv".toCharArray();
        char[] password = "Hello&77World!".toCharArray();

        // sha1 no pepper
        String hash = Hash.password(password)
                .algorithm(Type.PBKDF2_SHA1)
                .create();
        assertTrue(Hash.password(password)
                .verify(hash));

        // sha256 no pepper
        String hash2 = Hash.password(password)
                .algorithm(Type.PBKDF2_SHA256)
                .create();
        assertTrue(Hash.password(password)
                .verify(hash2));

        // sha512 no pepper
        String hash3 = Hash.password(password)
                .algorithm(Type.PBKDF2_SHA512)
                .create();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash3));

        // sha1 + pepper
        String hash4 = Hash.password(password)
                .pepper(pepper)
                .algorithm(Type.PBKDF2_SHA1)
                .create();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash4));

        // sha256 + pepper
        String hash5 = Hash.password(password)
                .pepper(pepper)
                .algorithm(Type.PBKDF2_SHA256)
                .create();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash5));

        // sha512 + pepper
        String hash6 = Hash.password(password)
                .pepper(pepper)
                .algorithm(Type.PBKDF2_SHA512)
                .create();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash6));
    }

    @Test
    public void hashLengthTests() throws InvalidHashException {

        char[] password = "Hello&77World!".toCharArray();

        // sha256 + hashLength
        String hash = Hash.password(password)
                .algorithm(Type.PBKDF2_SHA256)
                .hashLength(20)
                .create();
        assertTrue(Hash.password(password)
                .verify(hash));
    }

    @Test
    public void saltLengthTests() throws InvalidHashException {

        char[] password = "Hello&77World!".toCharArray();

        // sha512 + saltLength
        String hash = Hash.password(password)
                .algorithm(Type.PBKDF2_SHA512)
                .saltLength(16)
                .create();
        assertTrue(Hash.password(password)
                .verify(hash));
    }

    @Test
    public void lowFactorTests() throws InvalidHashException {

        int factor = 500;
        char[] pepper = "ZfMifTCEvjyDGIqv".toCharArray();
        char[] password = "Hello&77World!".toCharArray();

        // sha1 no pepper
        String hash = Hash.password(password)
                .algorithm(Type.PBKDF2_SHA1)
                .factor(factor)
                .create();
        assertTrue(Hash.password(password)
                .verify(hash));

        // sha256 no pepper
        String hash2 = Hash.password(password)
                .algorithm(Type.PBKDF2_SHA256)
                .factor(factor)
                .create();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash2));

        // sha512 no pepper
        String hash3 = Hash.password(password)
                .algorithm(Type.PBKDF2_SHA512)
                .factor(factor)
                .create();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash3));

        // sha1 + pepper
        String hash4 = Hash.password(password)
                .pepper(pepper)
                .algorithm(Type.PBKDF2_SHA1)
                .factor(factor)
                .create();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash4));

        // sha256 + pepper
        String hash5 = Hash.password(password)
                .pepper(pepper)
                .algorithm(Type.PBKDF2_SHA256)
                .factor(factor)
                .create();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash5));

        // sha512 + pepper
        String hash6 = Hash.password(password)
                .pepper(pepper)
                .algorithm(Type.PBKDF2_SHA512)
                .factor(factor)
                .create();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash6));
    }

    @Test
    public void highFactorTests() throws InvalidHashException {

        int factor = 20000;
        char[] pepper = "ZfMifTCEvjyDGIqv".toCharArray();
        char[] password = "Hello&77World!".toCharArray();

        // sha256 no pepper
        String hash2 = Hash.password(password)
                .algorithm(Type.PBKDF2_SHA256)
                .factor(factor)
                .create();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash2));
    }

    @Test
    public void invalidTests() {
        char[] password = "Hello&77World!".toCharArray();
        byte[] salt = HashUtils.randomSalt(PBKDF2.DEFAULT_SALT_LENGTH);

        try {
            // bad algorithm
            PBKDF2.create(password, salt, "PBKDFwhat?", PBKDF2.DEFAULT_ITERATIONS, PBKDF2.DEFAULT_HASH_LENGTH);
            fail("invalid PBKDF2 algorithm not detected");
        } catch (Exception e) {
            // good catch
        }

        try {
            // bad salt
            PBKDF2.create(password, null, "PBKDF2WithHmacSHA1", PBKDF2.DEFAULT_ITERATIONS, PBKDF2.DEFAULT_HASH_LENGTH);
            fail("invalid salt not detected");
        } catch (Exception e) {
            // good catch
        }

        try {
            // bad hash length
            PBKDF2.create(password, salt, "PBKDF2WithHmacSHA1", PBKDF2.DEFAULT_ITERATIONS, 0);
            fail("invalid hash length not detected");
        } catch (Exception e) {
            // good catch
        }
    }
}
