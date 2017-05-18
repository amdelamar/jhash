package com.amdelamar.jhash.exception;

public class BadOperationException extends Exception {

    private static final long serialVersionUID = 1L;

    public BadOperationException(String string) {
        super(string);
    }

    public BadOperationException(String string, Throwable ex) {
        super(string, ex);
    }
}
