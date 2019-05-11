package com.amdelamar.jhash.algorithms;

import com.amdelamar.jhash.Hash;
import com.amdelamar.jhash.exception.InvalidHashException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import static org.junit.Assert.*;

@RunWith(JUnit4.class)
public class BCryptTests {

    @Test
    public void constructorTests() {
        BCrypt algorithm = new BCrypt();
        assertNotNull(algorithm);
    }

    @Test
    public void defaultTests() throws InvalidHashException {

        char[] pepper = "ZfMifTCEvjyDGIqv".toCharArray();
        char[] password = "Hello&77World!".toCharArray();

        // bcrypt no pepper
        String hash = Hash.password(password)
                .algorithm(Type.BCRYPT)
                .factor(10)
                .create();
        assertTrue(Hash.password(password)
                .verify(hash));

        // bcrypt + pepper
        String hash2 = Hash.password(password)
                .pepper(pepper)
                .algorithm(Type.BCRYPT)
                .create();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash2));
    }

    @Test
    public void saltLengthTests() throws InvalidHashException {

        char[] pepper = "ZfMifTCEvjyDGIqv".toCharArray();
        char[] password = "Hello&77World!".toCharArray();

        // bcrypt + saltLength
        String hash3 = Hash.password(password)
                .pepper(pepper)
                .algorithm(Type.BCRYPT)
                .saltLength(24)
                .create();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash3));
    }

    @Test
    public void lowFactorTests() throws InvalidHashException {

        int parameter = 10;
        char[] pepper = "ZfMifTCEvjyDGIqv".toCharArray();
        char[] password = "Hello&77World!".toCharArray();

        // bcrypt no pepper
        String hash = Hash.password(password)
                .algorithm(Type.BCRYPT)
                .factor(parameter)
                .create();
        assertTrue(Hash.password(password)
                .verify(hash));

        // bcrypt + pepper
        String hash2 = Hash.password(password)
                .pepper(pepper)
                .algorithm(Type.BCRYPT)
                .factor(parameter)
                .create();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash2));
    }

    @Test
    public void highFactorTests() throws InvalidHashException {

        int parameter = 14;
        char[] pepper = "ZfMifTCEvjyDGIqv".toCharArray();
        char[] password = "Hello&77World!".toCharArray();

        // bcrypt + pepper
        String hash2 = Hash.password(password)
                .pepper(pepper)
                .algorithm(Type.BCRYPT)
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
                    .verify("bcrypt:13:60:16:n::$2a$10$YQ9urAM3RKuDtl1XaF99HrdpoIlB6ZhfaGR1T4yS4jlfMSPyeXehE.0Dway");
            fail("bad hash length not detected");
        } catch (Exception e) {
            // good error
        }

        try {
            // bad hash
            Hash.password(password)
                    .verify("bcrypt:13:66:16:n::~$2a$10$~YQ9urAM3RKuDtl1XaF99HrdpoIlB6ZhfaGR1T4yS4jlfMSPyeXehE.0Dway");
            fail("bad hash not detected");
        } catch (Exception e) {
            // good error
        }

        try {
            // bad hash format
            Hash.password(password)
                    .verify("bcrypt:13:66:16:n::$$2a$10$YQ9urAM3RKuDtl1XaF99HrdpoIlB6ZhfaGR1T4yS4jlfMSPyeXehE.0Dway");
            fail("bad hash not detected");
        } catch (Exception e) {
            // good error
        }

        try {
            // too high factor
            Hash.password(password)
                    .verify("bcrypt:31:66:16:n::$2a$31$YQ9urAM3RKuDtl1XaF99HrdpoIlB6ZhfaGR1T4yS4jlfMSPyeXehE.0Dway");
            fail("too high factor not detected");
        } catch (Exception e) {
            // good error
        }
    }
}
