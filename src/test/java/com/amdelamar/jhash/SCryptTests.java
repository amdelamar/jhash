package com.amdelamar.jhash;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.amdelamar.jhash.algorithms.SCrypt;
import com.amdelamar.jhash.algorithms.Type;
import com.amdelamar.jhash.exception.InvalidHashException;

@RunWith(JUnit4.class)
public class SCryptTests {
    
    @Test
    public void constructorTests() {
        SCrypt algorithm = new SCrypt();
        assertNotNull(algorithm);
    }

    @Test
    public void defaultTests() throws InvalidHashException {

        char[] pepper = "ZfMifTCEvjyDGIqv".toCharArray();
        char[] password = "Hello&77World!".toCharArray();

        // scrypt no pepper
        String hash = Hash.password(password)
                .algorithm(Type.SCRYPT)
                .create();
        assertTrue(Hash.password(password)
                .verify(hash));

        // scrypt + pepper
        String hash2 = Hash.password(password)
                .pepper(pepper)
                .algorithm(Type.SCRYPT)
                .create();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash2));
    }

    @Test
    public void saltLengthTests() throws InvalidHashException {

        char[] pepper = "ZfMifTCEvjyDGIqv".toCharArray();
        char[] password = "Hello&77World!".toCharArray();

        // scrypt + saltLength
        String hash3 = Hash.password(password)
                .pepper(pepper)
                .algorithm(Type.SCRYPT)
                .saltLength(16)
                .create();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash3));
    }

    @Test
    public void lowFactorTests() throws InvalidHashException {

        int parameter = 16384;
        char[] pepper = "ZfMifTCEvjyDGIqv".toCharArray();
        char[] password = "Hello&77World!".toCharArray();

        // scrypt no pepper
        String hash = Hash.password(password)
                .algorithm(Type.SCRYPT)
                .factor(parameter)
                .create();
        assertTrue(Hash.password(password)
                .verify(hash));

        // scrypt + pepper
        String hash2 = Hash.password(password)
                .pepper(pepper)
                .algorithm(Type.SCRYPT)
                .factor(parameter)
                .create();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash2));
    }

    @Test
    public void highFactorTests() throws InvalidHashException {

        int parameter = 262144;
        char[] pepper = "ZfMifTCEvjyDGIqv".toCharArray();
        char[] password = "Hello&77World!".toCharArray();

        // scrypt + pepper
        String hash2 = Hash.password(password)
                .pepper(pepper)
                .algorithm(Type.SCRYPT)
                .factor(parameter)
                .create();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash2));
    }

    @Test
    public void invalidHashTests() {
        char[] password = "HelloWorld".toCharArray();

        try {
            // bad hash length
            Hash.password(password)
                    .verify("scrypt:131072:70:24:n::$s0$e0801$Evw8WPqcEUy1n3PhZcP9pg==$lRbNPFoOdoBMFT0XUcZUPvIxCY8w+9DkUklXIqCOHks=");
            fail("bad hash length not detected");
        } catch (Exception e) {
            // good error
        }
    }
}
