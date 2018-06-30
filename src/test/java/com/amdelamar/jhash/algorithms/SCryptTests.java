package com.amdelamar.jhash.algorithms;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.amdelamar.jhash.Hash;
import com.amdelamar.jhash.exception.InvalidHashException;

@RunWith(JUnit4.class)
public class SCryptTests {
    
    @Test
    public void constructorTests() {
        SCrypt algorithm = new SCrypt();
        assertNotNull(algorithm);
    }

    @Test
    public void defaultTests() throws InvalidHashException {

        char[] pepper = "ZfMifTCEvjyDGIqv".toCharArray();
        char[] password = "Hello&77World!".toCharArray();

        // scrypt no pepper
        String hash = Hash.password(password)
                .algorithm(Type.SCRYPT)
                .create();
        assertTrue(Hash.password(password)
                .verify(hash));

        // scrypt + pepper
        String hash2 = Hash.password(password)
                .pepper(pepper)
                .algorithm(Type.SCRYPT)
                .create();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash2));
    }

    @Test
    public void saltLengthTests() throws InvalidHashException {

        char[] pepper = "ZfMifTCEvjyDGIqv".toCharArray();
        char[] password = "Hello&77World!".toCharArray();

        // scrypt + saltLength
        String hash3 = Hash.password(password)
                .pepper(pepper)
                .algorithm(Type.SCRYPT)
                .saltLength(16)
                .create();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash3));
    }

    @Test
    public void lowFactorTests() throws InvalidHashException {

        int parameter = 16384;
        char[] pepper = "ZfMifTCEvjyDGIqv".toCharArray();
        char[] password = "Hello&77World!".toCharArray();

        // scrypt no pepper
        String hash = Hash.password(password)
                .algorithm(Type.SCRYPT)
                .factor(parameter)
                .create();
        assertTrue(Hash.password(password)
                .verify(hash));

        // scrypt + pepper
        String hash2 = Hash.password(password)
                .pepper(pepper)
                .algorithm(Type.SCRYPT)
                .factor(parameter)
                .create();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash2));
    }

    @Test
    public void highFactorTests() throws InvalidHashException {

        int parameter = 262144;
        char[] pepper = "ZfMifTCEvjyDGIqv".toCharArray();
        char[] password = "Hello&77World!".toCharArray();

        // scrypt + pepper
        String hash2 = Hash.password(password)
                .pepper(pepper)
                .algorithm(Type.SCRYPT)
                .factor(parameter)
                .create();
        assertTrue(Hash.password(password)
                .pepper(pepper)
                .verify(hash2));
    }

    @Test
    public void invalidHashTests() {
        char[] password = "HelloWorld".toCharArray();
        
        try {
            // bad password
            Hash.password(new char[1])
                    .verify("scrypt:131072:80:24:n::$s0$e0801$Evw8WPqcEUy1n3PhZcP9pg==$lRbNPFoOdoBMFT0XUcZUPvIxCY8w+9DkUklXIqCOHks=");
            fail("bad password not detected");
        } catch (Exception e) {
            // good error
        }

        try {
            // bad hash length
            Hash.password(password)
                    .verify("scrypt:131072:70:24:n::$s0$e0801$Evw8WPqcEUy1n3PhZcP9pg==$lRbNPFoOdoBMFT0XUcZUPvIxCY8w+9DkUklXIqCOHks=");
            fail("bad hash length not detected");
        } catch (Exception e) {
            // good error
        }
        
        try {
            // bad hash
            Hash.password(password)
                    .verify("scrypt:131072:80:24:n::~$s0$e0801$~Evw8WPqcEUy1n3PhZcP9pg==$lRbNPFoOdoBMFT0XUcZUPvIxCY8w+9DkUklXIqCOHks=");
            fail("bad hash not detected");
        } catch (Exception e) {
            // good error
        }
        
        try {
            // bad hash format
            Hash.password(password)
                    .verify("scrypt:131072:80:24:n::$s1$e0801$Evw8WPqcEUy1n3PhZcP9pg==$lRbNPFoOdoBMFT0XUcZUPvIxCY8w+9DkUklXIqCOHks=");
            fail("bad hash not detected");
        } catch (Exception e) {
            // good error
        }
        
        try {
            // bad hash format
            Hash.password(password)
                    .verify("scrypt:131072:80:24:n::$$s0$e0801$Evw8WPqcEUy1n3PhZcP9pg==$$lRbNPFoOdoBMFT0XUcZUPvIxCY8w+9DkUklXIqCOHks=");
            fail("bad hash not detected");
        } catch (Exception e) {
            // good error
        }
        
        try {
            // too high factor
            Hash.password(password)
                    .verify("scrypt:13107200000000:80:24:n::~$s0$e0801$~Evw8WPqcEUy1n3PhZcP9pg==$lRbNPFoOdoBMFT0XUcZUPvIxCY8w+9DkUklXIqCOHks=");
            fail("too high factor not detected");
        } catch (Exception e) {
            // good error
        }
        
        try {
            // too low factor
            Hash.password(password)
                    .verify("scrypt:1:80:24:n::~$s0$e0801$~Evw8WPqcEUy1n3PhZcP9pg==$lRbNPFoOdoBMFT0XUcZUPvIxCY8w+9DkUklXIqCOHks=");
            fail("too low factor not detected");
        } catch (Exception e) {
            // good error
        }
    }
    
    @Test
    public void invalidTests() {
        byte[] password = "HelloWorld".getBytes();

        try {
            // too low cost
            SCrypt.scrypt(password, new byte[0], 1, SCrypt.BLOCKSIZE, SCrypt.PARALLEL, 32);
            fail("too low cost not detected");
        } catch (Exception e) {
            // good error
        }
        
        try {
            // bad cost
            SCrypt.scrypt(password, new byte[0], 3, SCrypt.BLOCKSIZE, SCrypt.PARALLEL, 32);
            fail("bad cost not detected");
        } catch (Exception e) {
            // good error
        }
        
        try {
            // too high cost
            SCrypt.scrypt(password, new byte[0], 1 + (Integer.MAX_VALUE / 128 / SCrypt.BLOCKSIZE), SCrypt.BLOCKSIZE, SCrypt.PARALLEL, 32);
            fail("too high cost not detected");
        } catch (Exception e) {
            // good error
        }
        
        try {
            // too high blocksize
            SCrypt.scrypt(password, new byte[0], 2, SCrypt.COST, SCrypt.COST, 32);
            fail("too high blocksize not detected");
        } catch (Exception e) {
            // good error
        }
        
        try {
            // bad hash format
            SCrypt.verify("HelloWorld", "$s$1$e0$801$Evw8WPqcEUy1n3PhZcP9pg==$lRbNPFoOdoBMFT0XUcZUPvIxCY8w+9DkUklXIqCOHks=");
            fail("bad hash format not detected");
        } catch (Exception e) {
            // good error
        }
        
        try {
            // bad hash format
            SCrypt.verify("HelloWorld", "$ss0$e0801$mzUhOD/ns1JCnwhsYPvIkg==$OlipMfOQJkCm62kY1m79AgIsfPzmIDdgz/fl/68EQ+Y=");
            fail("bad hash format not detected");
        } catch (Exception e) {
            // good error
        }
        
        // bad hash length
        assertFalse(SCrypt.verify("HelloWorld", "$s0$e0801$mzUhOD/ns1JCnwhsYPvIkg==$uOw06jt6FvimXSxEJipYYHsQ"));
    }
}
