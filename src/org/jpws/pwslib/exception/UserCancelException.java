package org.jpws.pwslib.exception;

import java.io.IOException;

/** An IOException which signals that the user has actively cancelled an 
 * IO related program function.
 * 
 */
public class UserCancelException extends IOException {

	public UserCancelException() {
	}

	public UserCancelException(String arg0) {
		super(arg0);
	}

	public UserCancelException(Throwable cause) {
		super(cause);
	}

	public UserCancelException(String message, Throwable cause) {
		super(message, cause);
	}

}
