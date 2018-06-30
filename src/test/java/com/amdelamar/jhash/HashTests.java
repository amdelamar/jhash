package com.amdelamar.jhash;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.amdelamar.jhash.algorithms.Type;
import com.amdelamar.jhash.exception.InvalidHashException;

@RunWith(JUnit4.class)
public class HashTests {
    
    @Test
    public void constructorTests() {
        Hash hash = new Hash();
        assertNotNull(hash);
    }

    @Test
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

    @Test
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

    @Test
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
    public void invalidAlgorithmTests() {
        char[] password = "foobar".toCharArray();

        try {
            String hash = Hash.password(password)
                    .algorithm(null)
                    .create();

            // verify
            Hash.password(password)
                    .verify(hash);

            // if ok, then fail
            fail("invalid algorithm not detected");

        } catch (IllegalArgumentException | InvalidHashException e) {
            // good catch
        }

        try {
            String hash = Hash.password(password)
                    .create();

            // change to bad algorithm
            hash = hash.replaceFirst("pbkdf2sha1:", "pbkdf2:");

            // verify
            Hash.password(password)
                    .verify(hash);

            // if ok, then fail
            fail("invalid hash algorithm not detected");

        } catch (IllegalArgumentException | InvalidHashException e) {
            // good catch
        }
        
        try {
            // bad algorithm name
            Hash.password(password)
                    .verify("jhash:64000:18:24:n:LZXY631xphycV5kaJ2WY0RRDqSfwiZ6L:uOw06jt6FvimXSxEJipYYHsQ");
            fail("bad algorithm not detected");
        } catch (Exception e) {
            // good error
        }
    }

    @Test
    public void nullPasswordTests() {
        boolean caught = false;

        try {
            // null password is bad
            Hash.password(null)
                    .create();
            caught = false;
        } catch (IllegalArgumentException e) {
            // the error we expect
            caught = true;
        } catch (Exception e) {
            // not good error
            caught = false;
        }
        assertTrue(caught);

        try {
            // empty password is bad
            Hash.password(new char[0])
                    .create();
            caught = false;
        } catch (IllegalArgumentException e) {
            // the error we expect
            caught = true;
        } catch (Exception e) {
            // not good error
            caught = false;
        }
        assertTrue(caught);
    }

    @Test
    public void nullPepperTests() {
        char[] password = "HelloWorld".toCharArray();
        boolean caught = false;

        try {
            // null pepper is ok
            Hash.password(password)
                    .pepper(null)
                    .create();
            caught = false;
        } catch (Exception e) {
            // not good error
            caught = true;
        }
        assertFalse(caught);

        try {
            // empty pepper is ok
            Hash.password(password)
                    .pepper(new char[0])
                    .create();
            caught = false;
        } catch (Exception e) {
            // not good error
            caught = true;
        }
        assertFalse(caught);
    }

    @Test
    public void nullHashTests() {
        char[] password = "HelloWorld".toCharArray();
        boolean caught = false;

        try {
            // null hash is bad
            Hash.password(password)
                    .verify(null);
            caught = false;
        } catch (Exception e) {
            // good error
            caught = true;
        }
        assertTrue(caught);

        try {
            // empty hash is bad
            Hash.password(password)
                    .verify("");
            caught = false;
        } catch (Exception e) {
            // good error
            caught = true;
        }
        assertTrue(caught);
    }
    
    @Test
    public void invalidHashTests() {
        char[] password = "HelloWorld".toCharArray();

        try {
            // hash with non-standard format
            Hash.password(password)
                    .verify("pbkdf2sha1:64000:LZXY631xphycV5kaJ2WY0RRDqSfwiZ6L:uOw06jt6FvimXSxEJipYYHsQ");
            fail("bad hash format not detected");
        } catch (Exception e) {
            // good error
        }
        
        try {
            // zero iterations
            Hash.password(password)
                    .verify("pbkdf2sha1:0:18:24:n:LZXY631xphycV5kaJ2WY0RRDqSfwiZ6L:uOw06jt6FvimXSxEJipYYHsQ");
            fail("zero iterations not detected");
        } catch (Exception e) {
            // good error
        }

        try {
            // bad iterations
            Hash.password(password)
                    .verify("pbkdf2sha1:64000a:18:24:n:LZXY631xphycV5kaJ2WY0RRDqSfwiZ6L:uOw06jt6FvimXSxEJipYYHsQ");
            fail("bad iterations not detected");
        } catch (Exception e) {
            // good error
        }
        
        try {
            // bad salt encoding
            Hash.password(password)
                    .verify("pbkdf2sha1:64000:18:24:n:~LZXY631xphycV5kaJ2WY0RRDqSfwiZ6L:uOw06jt6FvimXSxEJipYYHsQ");
            fail("bad salt encoding not detected");
        } catch (Exception e) {
            // good error
        }
        
        try {
            // bad hash size
            Hash.password(password)
                    .verify("pbkdf2sha1:64000:18a:24:n:LZXY631xphycV5kaJ2WY0RRDqSfwiZ6L:uOw06jt6FvimXSxEJipYYHsQ");
            fail("bad hash size not detected");
        } catch (Exception e) {
            // good error
        }
        
        try {
            // bad hash
            Hash.password(password)
                    .verify("pbkdf2sha1:64000:18:24:n:LZXY631xphycV5kaJ2WY0RRDqSfwiZ6L:uOw0");
            fail("bad hash length not detected");
        } catch (Exception e) {
            // good error
        }
        
        try {
            // bad salt size
            Hash.password(password)
                    .verify("pbkdf2sha1:64000:18:24a:n:LZXY631xphycV5kaJ2WY0RRDqSfwiZ6L:uOw06jt6FvimXSxEJipYYHsQ");
            fail("bad salt size not detected");
        } catch (Exception e) {
            // good error
        }
    }
}
