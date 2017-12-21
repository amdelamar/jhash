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

import com.amdelamar.jhash.exception.InvalidHashException;
import com.amdelamar.jhash.util.HashUtils;

@RunWith(JUnit4.class)
public class HashUtilsTests {

    @Test
    public void constructorTests() {
        @SuppressWarnings("unused")
        HashUtils util = new HashUtils();
    }
    
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
    }
    
    @Test
    public void invalidHashExceptionTests() {
        
        InvalidHashException ex = new InvalidHashException("Invalid");
        InvalidHashException ex2 = new InvalidHashException("Invalid2", new Throwable());
        
        assertEquals("Invalid", ex.getMessage());
        assertEquals("Invalid2", ex2.getMessage());
    }
}
