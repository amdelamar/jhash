package com.amdelamar.jhash;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.SecureRandom;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.amdelamar.jhash.util.HashUtils;

@RunWith(JUnit4.class)
public class HashUtilsTests {

    @Test
    public void saltTests() {

        SecureRandom sr = new SecureRandom();
        sr.setSeed(123456789l);

        String s1 = new String(HashUtils.randomSalt());
        String s2 = new String(HashUtils.randomSalt(Hash.SALT_BYTE_SIZE));
        String s3 = new String(HashUtils.randomSalt(sr));
        String s4 = new String(HashUtils.randomSalt(sr, Hash.SALT_BYTE_SIZE));

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

        assertEquals(s1.length(), Hash.SALT_BYTE_SIZE);
        assertEquals(s2.length(), Hash.SALT_BYTE_SIZE);
        assertEquals(s3.length(), Hash.SALT_BYTE_SIZE);
        assertEquals(s4.length(), Hash.SALT_BYTE_SIZE);
    }

    @Test
    public void slowEqualTests() {

        String hello = "Hello World!";
        String hello64 = "SGVsbG8gV29ybGQh";

        boolean slow1 = HashUtils.slowEquals(hello.getBytes(), hello64.getBytes());
        assertFalse(slow1);

        boolean slow2 = HashUtils.slowEquals(HashUtils.encodeBase64(hello.getBytes()).getBytes(),
                hello64.getBytes());
        assertTrue(slow2);
    }

    @Test
    public void base64Tests() {
        // Validate the Base64 encode/deocde methods.
        String hello = "Hello World!";
        String hello64 = "SGVsbG8gV29ybGQh";

        assertEquals(hello64, HashUtils.encodeBase64(hello.getBytes()));
        assertEquals(hello, new String(HashUtils.decodeBase64(hello64)));
    }
}
