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
public class SCryptTests {

    @Test
    public void defaultTests() throws BadOperationException, InvalidHashException, NoSuchAlgorithmException {

        char[] pepper = "ZfMifTCEvjyDGIqv".toCharArray();
        char[] password = "Hello&77World!".toCharArray();

        // scrypt no pepper
        char[] hash = Hash.password(password)
                .algorithm(Type.SCRYPT)
                .create()
                .toCharArray();
        assertTrue(Hash.password(password)
                .verify(hash));

        // scrypt + pepper
        char[] hash2 = Hash.password(password)
                .pepper(pepper)
                .algorithm(Type.SCRYPT)
                .create()
                .toCharArray();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash2));
    }

    @Test
    public void lowFactorTests() throws BadOperationException, InvalidHashException, NoSuchAlgorithmException {

        int parameter = 16384;
        char[] pepper = "ZfMifTCEvjyDGIqv".toCharArray();
        char[] password = "Hello&77World!".toCharArray();

        // scrypt no pepper
        char[] hash = Hash.password(password)
                .algorithm(Type.SCRYPT)
                .factor(parameter)
                .create()
                .toCharArray();
        assertTrue(Hash.password(password)
                .verify(hash));

        // scrypt + pepper
        char[] hash2 = Hash.password(password)
                .pepper(pepper)
                .algorithm(Type.SCRYPT)
                .factor(parameter)
                .create()
                .toCharArray();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash2));
    }

    @Test
    public void highFactorTests() throws BadOperationException, InvalidHashException, NoSuchAlgorithmException {

        int parameter = 262144;
        char[] pepper = "ZfMifTCEvjyDGIqv".toCharArray();
        char[] password = "Hello&77World!".toCharArray();

        // scrypt + pepper
        char[] hash2 = Hash.password(password)
                .pepper(pepper)
                .algorithm(Type.SCRYPT)
                .factor(parameter)
                .create()
                .toCharArray();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash2));
    }
}
