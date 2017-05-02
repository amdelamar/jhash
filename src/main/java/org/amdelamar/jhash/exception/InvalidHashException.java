package org.amdelamar.jhash.exception;

public class InvalidHashException extends Exception {

    private static final long serialVersionUID = 1L;

    public InvalidHashException(String string) {
        super(string);
    }

    public InvalidHashException(String string, Throwable ex) {
        super(string, ex);
    }

}
