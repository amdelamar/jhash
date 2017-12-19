package com.amdelamar.jhash;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.amdelamar.jhash.algorithms.Type;
import com.amdelamar.jhash.exception.InvalidHashException;

@RunWith(JUnit4.class)
public class HashTests {

    public void truncatedHashTest() {

        char[] password = "Hello World!".toCharArray();
        String badHash = "";
        String goodHash = Hash.password(password)
                .create();
        int badHashLength = goodHash.length();

        do {
            // Make sure truncated hashes don't validate.
            badHashLength -= 1;
            badHash = goodHash.substring(0, badHashLength);

            boolean raised = false;
            try {
                Hash.password(password)
                        .verify(badHash);
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

    public void verifyTests() throws InvalidHashException {

        boolean failure = false;
        for (int i = 0; i < 10; i++) {
            String password = "000" + i;
            String hash = Hash.password(password.toCharArray())
                    .create();
            String secondHash = Hash.password(password.toCharArray())
                    .create();
            if (hash.equals(secondHash)) {
                failure = true;
            }
            String wrongPassword = "000" + (i + 1);
            if (Hash.password(wrongPassword.toCharArray())
                    .verify(hash)) {
                failure = true;
            }
            if (!Hash.password(password.toCharArray())
                    .verify(hash)) {
                failure = true;
            }
            assertFalse(failure);
        }
    }

    public void breakTests() throws InvalidHashException {
        char[] password = "foobar".toCharArray();
        // sha1
        String hash = Hash.password(password)
                .create();
        // accidentally change algorithms
        hash = hash.replaceFirst("pbkdf2sha1:", "pbkdf2sha256:");
        assertFalse(Hash.password(password)
                .verify(hash));

        // sha2
        hash = Hash.password(password)
                .algorithm(Type.PBKDF2_SHA256)
                .create();
        assertTrue(Hash.password(password)
                .verify(hash));
    }

    @Test
    public void nullTests() {
        // null algorithm type
        boolean caught = false;
        try {
            Hash.password(null)
                    .create();
        } catch (IllegalArgumentException e) {
            // the error we expect
            caught = true;
        } catch (Exception e) {
            // not good error
            caught = false;
        }
        assertTrue(caught);
    }
}
