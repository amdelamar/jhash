package org.amdelamar.jhash;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.amdelamar.jhash.exception.BadOperationException;
import org.amdelamar.jhash.exception.InvalidHashException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class Tests {
    
    @Test
    public void base64Tests() {
        // Validate the Base64 encode/deocde methods.
        String hello = "Hello World!";
        String hello64 = "SGVsbG8gV29ybGQh";
        
        assertEquals(hello64, Hash.encodeBase64(hello.getBytes()));
        assertEquals(hello, new String(Hash.decodeBase64(hello64)));
    }

    @Test
    public void truncatedHashTest() {
        // Make sure truncated hashes don't validate.
        String userString = "password!";
        String goodHash = "";
        String badHash = "";
        int badHashLength = 0;

        try {
            goodHash = Hash.create(userString);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }
        badHashLength = goodHash.length();

        do {
            badHashLength -= 1;
            badHash = goodHash.substring(0, badHashLength);

            boolean raised = false;
            try {
                Hash.verify(userString, badHash);
            } catch (InvalidHashException ex) {
                raised = true;
            } catch (Exception ex) {
                System.out.println(ex.getMessage());
                System.exit(1);
            }

            if (!raised) {
                System.out.println("Truncated hash test: FAIL " + "(At hash length of " + badHashLength + ")");
                System.exit(1);
            }

            // The loop goes on until it is two characters away from the last : it
            // finds. This is because the PBKDF2 function requires a hash that's at
            // least 2 characters long.
        } while (badHash.charAt(badHashLength - 3) != ':');
    }

    @Test
    public void basicTests() throws InvalidHashException, BadOperationException {
        // Test password validation
        boolean failure = false;
        for (int i = 0; i < 10; i++) {
            String password = "" + i;
            String hash = Hash.create(password);
            String secondHash = Hash.create(password);
            if (hash.equals(secondHash)) {
                System.out.println("FAILURE: TWO HASHES ARE EQUAL!");
                failure = true;
            }
            String wrongPassword = "" + (i + 1);
            if (Hash.verify(wrongPassword, hash)) {
                System.out.println("FAILURE: WRONG PASSWORD ACCEPTED!");
                failure = true;
            }
            if (!Hash.verify(password, hash)) {
                System.out.println("FAILURE: GOOD PASSWORD NOT ACCEPTED!");
                failure = true;
            }
        }
        assertFalse(failure);
    }

    @Test
    public void testHashFunctionChecking() throws InvalidHashException, BadOperationException {
        String hash = Hash.create("foobar");
        hash = hash.replaceFirst("sha1:", "sha256:");

        boolean raised = false;
        try {
            Hash.verify("foobar", hash);
        } catch (BadOperationException ex) {
            raised = true;
        }
        assertTrue(raised);
    }
}
