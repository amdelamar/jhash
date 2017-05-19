package com.amdelamar.jhash;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.amdelamar.jhash.util.HashUtils;

@RunWith(JUnit4.class)
public class HashUtilsTests {

    @Test
    public void base64Tests() {
        // Validate the Base64 encode/deocde methods.
        String hello = "Hello World!";
        String hello64 = "SGVsbG8gV29ybGQh";

        assertEquals(hello64, HashUtils.encodeBase64(hello.getBytes()));
        assertEquals(hello, new String(HashUtils.decodeBase64(hello64)));
    }
}
