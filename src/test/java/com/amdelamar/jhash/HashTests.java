package com.amdelamar.jhash;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.NoSuchAlgorithmException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.amdelamar.jhash.algorithms.Type;
import com.amdelamar.jhash.exception.BadOperationException;
import com.amdelamar.jhash.exception.InvalidHashException;

@RunWith(JUnit4.class)
public class HashTests {

    @Test
    public void truncatedHashTest() throws NoSuchAlgorithmException, BadOperationException {
        
        String password = "Hello World!";
        String badHash = "";
        String goodHash = Hash.create(password);
        int badHashLength = goodHash.length();

        do {
            // Make sure truncated hashes don't validate.
            badHashLength -= 1;
            badHash = goodHash.substring(0, badHashLength);

            boolean raised = false;
            try {
                Hash.verify(password, badHash);
            } catch (Exception e) {
                // this is good
                raised = true;
            }
            assertTrue(raised);

            // The loop goes on until it is two characters away from the last : it
            // finds. This is because the PBKDF2 function requires a hash that's at
            // least 2 characters long.
        } while (badHash.charAt(badHashLength - 3) != ':');
    }

    @Test
    public void verifyTests()
            throws InvalidHashException, BadOperationException, NoSuchAlgorithmException {

        boolean failure = false;
        for (int i = 0; i < 10; i++) {
            String password = "" + i;
            String hash = Hash.create(password);
            String secondHash = Hash.create(password);
            if (hash.equals(secondHash)) {
                failure = true;
            }
            String wrongPassword = "" + (i + 1);
            if (Hash.verify(wrongPassword, hash)) {
                failure = true;
            }
            if (!Hash.verify(password, hash)) {
                failure = true;
            }
            assertFalse(failure);
        }
    }

    @Test
    public void breakTests()
            throws InvalidHashException, BadOperationException, NoSuchAlgorithmException {
        // sha1
        String hash = Hash.create("foobar");
        // accidentally change algorithms
        hash = hash.replaceFirst("pbkdf2sha1:", "pbkdf2sha256:");
        assertFalse(Hash.verify("foobar", hash));

        // sha2
        hash = Hash.create("foobar", Type.PBKDF2_SHA256);
        assertTrue(Hash.verify("foobar", hash));
    }
    
    @Test
    public void nullTests() {
        // null algorithm type
        boolean caught = false;
        try {
            Hash.create("foobar", null);
        } catch (NoSuchAlgorithmException e) {
            // the error we expect
            caught = true;
        } catch (BadOperationException e) {
            // not good error
            caught = false;
        }
        assertTrue(caught);
    }
}
