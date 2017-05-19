package com.amdelamar.jhash;

import static org.junit.Assert.assertTrue;

import java.security.NoSuchAlgorithmException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.amdelamar.jhash.exception.BadOperationException;
import com.amdelamar.jhash.exception.InvalidHashException;

@RunWith(JUnit4.class)
public class PBKDF2Tests {

    @Test
    public void defaultTests()
            throws BadOperationException, InvalidHashException, NoSuchAlgorithmException {

        String pepper = "ZfMifTCEvjyDGIqv";
        String password = "Hello&77World!";

        // sha1 no pepper
        String hash = Hash.create(password, Hash.PBKDF2_HMACSHA1);
        assertTrue(Hash.verify(password, hash));

        // sha256 no pepper
        String hash2 = Hash.create(password, Hash.PBKDF2_HMACSHA256);
        assertTrue(Hash.verify(password, pepper, hash2));

        // sha512 no pepper
        String hash3 = Hash.create(password, Hash.PBKDF2_HMACSHA512);
        assertTrue(Hash.verify(password, pepper, hash3));

        // sha1 + pepper
        String hash4 = Hash.create(password, pepper, Hash.PBKDF2_HMACSHA1);
        assertTrue(Hash.verify(password, pepper, hash4));

        // sha256 + pepper
        String hash5 = Hash.create(password, pepper, Hash.PBKDF2_HMACSHA256);
        assertTrue(Hash.verify(password, pepper, hash5));

        // sha512 + pepper
        String hash6 = Hash.create(password, pepper, Hash.PBKDF2_HMACSHA512);
        assertTrue(Hash.verify(password, pepper, hash6));
    }
    
    @Test
    public void lowParameterTests()
            throws BadOperationException, InvalidHashException, NoSuchAlgorithmException {

        int parameter = 1000;
        String pepper = "ZfMifTCEvjyDGIqv";
        String password = "Hello&77World!";

        // sha1 no pepper
        String hash = Hash.create(password, Hash.PBKDF2_HMACSHA1, parameter);
        assertTrue(Hash.verify(password, hash));

        // sha256 no pepper
        String hash2 = Hash.create(password, Hash.PBKDF2_HMACSHA256, parameter);
        assertTrue(Hash.verify(password, pepper, hash2));

        // sha512 no pepper
        String hash3 = Hash.create(password, Hash.PBKDF2_HMACSHA512, parameter);
        assertTrue(Hash.verify(password, pepper, hash3));

        // sha1 + pepper
        String hash4 = Hash.create(password, pepper, Hash.PBKDF2_HMACSHA1, parameter);
        assertTrue(Hash.verify(password, pepper, hash4));

        // sha256 + pepper
        String hash5 = Hash.create(password, pepper, Hash.PBKDF2_HMACSHA256, parameter);
        assertTrue(Hash.verify(password, pepper, hash5));

        // sha512 + pepper
        String hash6 = Hash.create(password, pepper, Hash.PBKDF2_HMACSHA512, parameter);
        assertTrue(Hash.verify(password, pepper, hash6));
    }
    
    @Test
    public void highParameterTests()
            throws BadOperationException, InvalidHashException, NoSuchAlgorithmException {

        int parameter = 250000;
        String pepper = "ZfMifTCEvjyDGIqv";
        String password = "Hello&77World!";

        // sha256 no pepper
        String hash2 = Hash.create(password, Hash.PBKDF2_HMACSHA256, parameter);
        assertTrue(Hash.verify(password, pepper, hash2));
    }
}
