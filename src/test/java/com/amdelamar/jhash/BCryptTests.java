package com.amdelamar.jhash;

import static org.junit.Assert.assertTrue;

import java.security.NoSuchAlgorithmException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.amdelamar.jhash.exception.BadOperationException;
import com.amdelamar.jhash.exception.InvalidHashException;

@RunWith(JUnit4.class)
public class BCryptTests {

    @Test
    public void defaultTests()
            throws BadOperationException, InvalidHashException, NoSuchAlgorithmException {

        String pepper = "ZfMifTCEvjyDGIqv";
        String password = "Hello&77World!";

        // bcrypt no pepper
        String hash = Hash.create(password, Hash.BCRYPT);
        assertTrue(Hash.verify(password, hash));

        // bcrypt + pepper
        String hash2 = Hash.create(password, pepper, Hash.BCRYPT);
        assertTrue(Hash.verify(password, pepper, hash2));
    }
    
    @Test
    public void lowParameterTests()
            throws BadOperationException, InvalidHashException, NoSuchAlgorithmException {

        int parameter = 10;
        String pepper = "ZfMifTCEvjyDGIqv";
        String password = "Hello&77World!";

        // bcrypt no pepper
        String hash = Hash.create(password, Hash.BCRYPT, parameter);
        assertTrue(Hash.verify(password, hash));

        // bcrypt + pepper
        String hash2 = Hash.create(password, pepper, Hash.BCRYPT, parameter);
        assertTrue(Hash.verify(password, pepper, hash2));
    }
    
    @Test
    public void highParameterTests()
            throws BadOperationException, InvalidHashException, NoSuchAlgorithmException {

        int parameter = 16;
        String pepper = "ZfMifTCEvjyDGIqv";
        String password = "Hello&77World!";

        // bcrypt + pepper
        String hash2 = Hash.create(password, pepper, Hash.BCRYPT, parameter);
        assertTrue(Hash.verify(password, pepper, hash2));
    }
}
