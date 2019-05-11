package com.amdelamar.jhash.util;

import com.amdelamar.jhash.exception.InvalidHashException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.security.SecureRandom;

import static org.junit.Assert.*;

@RunWith(JUnit4.class)
public class HashUtilsTests {

    @Test
    public void saltTests() {

        SecureRandom sr = new SecureRandom();
        sr.setSeed(123456789l);

        String s1 = HashUtils.encodeBase64(HashUtils.randomSalt());
        String s2 = HashUtils.encodeBase64(HashUtils.randomSalt(24));
        String s3 = HashUtils.encodeBase64(HashUtils.randomSalt(sr));
        String s4 = HashUtils.encodeBase64(HashUtils.randomSalt(sr, 24));

        assertNotNull(s1);
        assertNotNull(s2);
        assertNotNull(s3);
        assertNotNull(s4);

        assertNotEquals(s1, s2);
        assertNotEquals(s1, s3);
        assertNotEquals(s1, s4);
        assertNotEquals(s2, s3);
        assertNotEquals(s2, s4);
        assertNotEquals(s3, s4);
    }

    @Test
    public void slowEqualTests() {

        String hello = "Hello World!";
        String hello64 = "SGVsbG8gV29ybGQh";

        boolean slow1 = HashUtils.slowEquals(hello.getBytes(), hello64.getBytes());
        assertFalse(slow1);

        boolean slow2 = HashUtils.slowEquals(HashUtils.encodeBase64(hello.getBytes())
                .getBytes(), hello64.getBytes());
        assertTrue(slow2);

        boolean slow3 = HashUtils.slowEquals(hello64.getBytes(), hello.getBytes());
        assertFalse(slow3);
    }

    @Test
    public void base64Tests() {
        // Validate the Base64 encode/deocde methods.
        String hello = "Hello World!";
        String hello64 = "SGVsbG8gV29ybGQh";

        assertEquals(hello64, HashUtils.encodeBase64(hello.getBytes()));
        assertEquals(hello, new String(HashUtils.decodeBase64(hello64)));

        String loremispum = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt " +
                "ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris " +
                "nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit " +
                "esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in " +
                "culpa qui officia deserunt mollit anim id est laborum.";
        String loremispum64 = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdCwgc2VkIGRvIGV" +
                "pdXNtb2QgdGVtcG9yIGluY2lkaWR1bnQgdXQgbGFib3JlIGV0IGRvbG9yZSBtYWduYSBhbGlxdWEuIFV0IGVuaW0gYWQgbWluaW0g" +
                "dmVuaWFtLCBxdWlzIG5vc3RydWQgZXhlcmNpdGF0aW9uIHVsbGFtY28gbGFib3JpcyBuaXNpIHV0IGFsaXF1aXAgZXggZWEgY29tb" +
                "W9kbyBjb25zZXF1YXQuIER1aXMgYXV0ZSBpcnVyZSBkb2xvciBpbiByZXByZWhlbmRlcml0IGluIHZvbHVwdGF0ZSB2ZWxpdCBlc3" +
                "NlIGNpbGx1bSBkb2xvcmUgZXUgZnVnaWF0IG51bGxhIHBhcmlhdHVyLiBFeGNlcHRldXIgc2ludCBvY2NhZWNhdCBjdXBpZGF0YXQ" +
                "gbm9uIHByb2lkZW50LCBzdW50IGluIGN1bHBhIHF1aSBvZmZpY2lhIGRlc2VydW50IG1vbGxpdCBhbmltIGlkIGVzdCBsYWJvcnVt" +
                "Lg==";

        assertEquals(loremispum64, HashUtils.encodeBase64(loremispum.getBytes()));
        assertEquals(loremispum, new String(HashUtils.decodeBase64(loremispum64)));
    }

    @Test
    public void invalidHashExceptionTests() {

        InvalidHashException ex = new InvalidHashException("Invalid");
        InvalidHashException ex2 = new InvalidHashException("Invalid2", new Throwable());

        assertEquals("Invalid", ex.getMessage());
        assertEquals("Invalid2", ex2.getMessage());
    }
}
