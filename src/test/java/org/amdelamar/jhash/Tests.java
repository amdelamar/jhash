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
                System.out.println(
                        "Truncated hash test: FAIL " + "(At hash length of " + badHashLength + ")");
                System.exit(1);
            }
            assertTrue(raised);

            // The loop goes on until it is two characters away from the last : it
            // finds. This is because the PBKDF2 function requires a hash that's at
            // least 2 characters long.
        } while (badHash.charAt(badHashLength - 3) != ':');
    }

    @Test
    public void verifyTests() throws InvalidHashException, BadOperationException {
        // Test password validation
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
    public void breakTests() throws InvalidHashException, BadOperationException {
        // sha1
        String hash = Hash.create("foobar");
        // accidentally change algorithms
        hash = hash.replaceFirst("pbkdf2sha1:", "pbkdf2sha256:");
        assertFalse(Hash.verify("foobar", hash));

        // sha2
        hash = Hash.create("foobar", Hash.PBKDF2_HMACSHA256);
        assertTrue(Hash.verify("foobar", hash));
    }

    @Test
    public void pbkdf2Tests() throws BadOperationException, InvalidHashException {

        String pepper = "ZfMifTCEvjyDGIqv";
        String password = "Hello&77World!";

        try {
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

        } catch (BadOperationException | InvalidHashException e) {
            e.printStackTrace();
        }
    }
    
    @Test
    public void bcryptTests() throws BadOperationException, InvalidHashException {

        String pepper = "ZfMifTCEvjyDGIqv";
        String password = "Hello&77World!";

        try {
            // bcrypt no pepper
            String hash = Hash.create(password, Hash.BCRYPT);
            assertTrue(Hash.verify(password, hash));

            // bcrypt + pepper
            String hash2 = Hash.create(password, pepper, Hash.BCRYPT);
            assertTrue(Hash.verify(password, pepper, hash2));

        } catch (BadOperationException | InvalidHashException e) {
            e.printStackTrace();
        }
    }
}
