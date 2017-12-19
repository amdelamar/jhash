package com.amdelamar.jhash;

import static org.junit.Assert.assertTrue;

import java.security.NoSuchAlgorithmException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.amdelamar.jhash.algorithms.Type;
import com.amdelamar.jhash.exception.BadOperationException;
import com.amdelamar.jhash.exception.InvalidHashException;

@RunWith(JUnit4.class)
public class PBKDF2Tests {

    @Test
    public void defaultTests() throws BadOperationException, InvalidHashException, NoSuchAlgorithmException {

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
                .pepper(pepper)
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
    public void saltLengthTests() throws NoSuchAlgorithmException, BadOperationException, InvalidHashException {

        char[] pepper = "ZfMifTCEvjyDGIqv".toCharArray();
        char[] password = "Hello&77World!".toCharArray();

        // sha512 + saltLength
        String hash3 = Hash.password(password)
                .pepper(pepper)
                .algorithm(Type.PBKDF2_SHA512)
                .saltLength(24)
                .create();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash3));
    }

    @Test
    public void lowFactorTests() throws BadOperationException, InvalidHashException, NoSuchAlgorithmException {

        int factor = 1000;
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
    public void highFactorTests() throws BadOperationException, InvalidHashException, NoSuchAlgorithmException {

        int factor = 250000;
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
}
