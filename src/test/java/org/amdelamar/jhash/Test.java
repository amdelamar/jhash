package org.amdelamar.jhash;

import org.amdelamar.jhash.Hash;
import org.amdelamar.jhash.exception.BadOperationException;
import org.amdelamar.jhash.exception.InvalidHashException;

public class Test {

    public static void main(String[] args) {
        basicTests();
        truncatedHashTest();
        testHashFunctionChecking();
    }

    // Make sure truncated hashes don't validate.
    public static void truncatedHashTest() {
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

        System.out.println("Truncated hash test: pass");
    }

    /**
     * Tests the basic functionality of the PasswordStorage class
     *
     * @param args
     *            ignored
     */
    public static void basicTests() {
        try {
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
            if (failure) {
                System.out.println("TESTS FAILED!");
                System.exit(1);
            }
        } catch (Exception ex) {
            System.out.println("ERROR: " + ex);
            System.exit(1);
        }
    }

    public static void testHashFunctionChecking() {
        try {
            String hash = Hash.create("foobar");
            hash = hash.replaceFirst("sha1:", "sha256:");

            boolean raised = false;
            try {
                Hash.verify("foobar", hash);
            } catch (BadOperationException ex) {
                raised = true;
            }

            if (raised) {
                System.out.println("Algorithm swap: pass");
            } else {
                System.out.println("Algorithm swap: FAIL");
                System.exit(1);
            }
        } catch (Exception e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }

    }
}
