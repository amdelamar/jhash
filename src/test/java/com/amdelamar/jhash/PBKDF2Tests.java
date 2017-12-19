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
        char[] hash = Hash.password(password)
                .algorithm(Type.PBKDF2_SHA1)
                .create()
                .toCharArray();
        assertTrue(Hash.password(password)
                .verify(hash));

        // sha256 no pepper
        char[] hash2 = Hash.password(password)
                .algorithm(Type.PBKDF2_SHA256)
                .create()
                .toCharArray();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash2));

        // sha512 no pepper
        char[] hash3 = Hash.password(password)
                .algorithm(Type.PBKDF2_SHA512)
                .create()
                .toCharArray();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash3));

        // sha1 + pepper
        char[] hash4 = Hash.password(password)
                .pepper(pepper)
                .algorithm(Type.PBKDF2_SHA1)
                .create()
                .toCharArray();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash4));

        // sha256 + pepper
        char[] hash5 = Hash.password(password)
                .pepper(pepper)
                .algorithm(Type.PBKDF2_SHA256)
                .create()
                .toCharArray();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash5));

        // sha512 + pepper
        char[] hash6 = Hash.password(password)
                .pepper(pepper)
                .algorithm(Type.PBKDF2_SHA512)
                .create()
                .toCharArray();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash6));
    }

    @Test
    public void lowFactorTests() throws BadOperationException, InvalidHashException, NoSuchAlgorithmException {

        int factor = 1000;
        char[] pepper = "ZfMifTCEvjyDGIqv".toCharArray();
        char[] password = "Hello&77World!".toCharArray();

        // sha1 no pepper
        char[] hash = Hash.password(password)
                .algorithm(Type.PBKDF2_SHA1)
                .factor(factor)
                .create()
                .toCharArray();
        assertTrue(Hash.password(password)
                .verify(hash));

        // sha256 no pepper
        char[] hash2 = Hash.password(password)
                .algorithm(Type.PBKDF2_SHA256)
                .factor(factor)
                .create()
                .toCharArray();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash2));

        // sha512 no pepper
        char[] hash3 = Hash.password(password)
                .algorithm(Type.PBKDF2_SHA512)
                .factor(factor)
                .create()
                .toCharArray();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash3));

        // sha1 + pepper
        char[] hash4 = Hash.password(password)
                .pepper(pepper)
                .algorithm(Type.PBKDF2_SHA1)
                .factor(factor)
                .create()
                .toCharArray();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash4));

        // sha256 + pepper
        char[] hash5 = Hash.password(password)
                .pepper(pepper)
                .algorithm(Type.PBKDF2_SHA256)
                .factor(factor)
                .create()
                .toCharArray();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash5));

        // sha512 + pepper
        char[] hash6 = Hash.password(password)
                .pepper(pepper)
                .algorithm(Type.PBKDF2_SHA512)
                .factor(factor)
                .create()
                .toCharArray();
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
        char[] hash2 = Hash.password(password)
                .algorithm(Type.PBKDF2_SHA256)
                .factor(factor)
                .create()
                .toCharArray();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash2));
    }
}
