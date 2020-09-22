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
    public void customSaltTests() throws InvalidHashException {
        char[] password = "Hello&77World!".toCharArray();
        // bcrypt + custom salt
        String hash = Hash.password(password)
                .algorithm(Type.BCRYPT)
                .saltLength(1) // should be overridden
                .salt("pretzel".getBytes())
                .saltLength(10) // should be ignored
                .create();
        assertTrue(Hash.password(password)
                .verify(hash));
    }

    @Test
    public void defaultFactorTests() throws InvalidHashException {

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
    public void lowFactorTests() throws InvalidHashException {
        char[] password = "HelloWorld".toCharArray();

        String hash = Hash.password(password).algorithm(Type.BCRYPT).factor(9).create();
        assertTrue(Hash.password(password).verify(hash));

        String hash2 = "bcrypt:4:60:16:n::$2y$04$lkEs3RSX0FKeaZhuFrarfuIioYwEihR56kYOFlLy.26aQ7vEq7K8q";
        assertTrue(Hash.password(password).verify(hash2));

        String hash3 = "bcrypt:9:60:16:n::$2y$09$d0pDK4uPB50MGVAqh1i6mu/GHHMcx/op4SmXMd4clWZ.uaXsNNvs.";
        assertTrue(Hash.password(password).verify(hash3));
    }

    @Test
    public void tooLowFactorTests() {
        char[] password = "HelloWorld".toCharArray();

        try {
            Hash.password(password).algorithm(Type.BCRYPT).factor(1).create();
            fail("bad rounds (factor) not detected");
        }
        catch (Exception e) {
            // good error
        }

        try {
            Hash.password(password).algorithm(Type.BCRYPT).factor(3).create();
            fail("bad rounds (factor) not detected");
        }
        catch (Exception e) {
            // good error
        }
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

    @Test
    public void revisionHashTests() throws Exception {
        char[] password = "HelloWorld".toCharArray();

        // revision 'a' with 10 rounds
        assertTrue(Hash.password(password).verify(
                "bcrypt:10:60:16:n::$2a$10$w6sTWVowepjgQxI4epepFuQS66Yt.ijLaXf.oa.L1PjI7TnKucZ4S"));

        // revision 'b' with 12 rounds
        assertTrue(Hash.password(password).verify(
                "bcrypt:12:60:16:n::$2b$12$tcniI9p9QJ0bppCWsTFDTuysUNUxjIGOyXE8205SpPmZZWHYDc0pq"));

        // revision 'y' with 13 rounds
        assertTrue(Hash.password(password).verify(
                "bcrypt:13:60:16:n::$2y$13$HHQ1CbHAQ/9u2wXjYqwApuySKPrdPqxeSakNspEWJ9S.AbHJojrXu"));
    }

    @Test
    public void invalidRevisionHashTests() {
        char[] password = "HelloWorld".toCharArray();

        try {
            // revision 'A' invalid
            Hash.password(password)
                    .verify("bcrypt:13:60:16:n::$2A$13$u.cohr7sjMW9HA6.QoPlnuEBeaRcmoHWLGEfigfC8OtGL98gjz4MK");
            fail("invalid revision 'A' not detected");
        } catch (Exception e) {
            // good error
        }
    }
}
