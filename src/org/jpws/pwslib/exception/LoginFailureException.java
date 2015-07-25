package org.jpws.pwslib.exception;

import java.io.IOException;

/** Thrown to indicate that an attempt to login into some device
 * or network repository has failed.
 *  
 * @author wolfgang keller
 *
 */
public class LoginFailureException extends IOException {

    public LoginFailureException() {
    }

    public LoginFailureException(String message) {
        super(message);
    }


    
}
