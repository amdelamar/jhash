package com.amdelamar.jhash;

import static org.junit.Assert.assertTrue;

import java.security.NoSuchAlgorithmException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.amdelamar.jhash.exception.BadOperationException;
import com.amdelamar.jhash.exception.InvalidHashException;

@RunWith(JUnit4.class)
public class SCryptTests {

    @Test
    public void scryptTests()
            throws BadOperationException, InvalidHashException, NoSuchAlgorithmException {

        String pepper = "ZfMifTCEvjyDGIqv";
        String password = "Hello&77World!";

        // scrypt no pepper
        String hash = Hash.create(password, Hash.SCRYPT);
        assertTrue(Hash.verify(password, hash));

        // scrypt + pepper
        String hash2 = Hash.create(password, pepper, Hash.SCRYPT);
        assertTrue(Hash.verify(password, pepper, hash2));
    }
}
