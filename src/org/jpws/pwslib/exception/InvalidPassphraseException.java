/*
 * $Id: InvalidPassphraseException.java,v 1.1.1.1 2006/09/17 17:30:01 Besitzer Exp $
 * 
 * This file is provided under the standard terms of the Artistic Licence.  See the
 * LICENSE file that comes with this package for details.
 */
package org.jpws.pwslib.exception;

/**
 * An exception thrown to indicate that an encryption passphrase is not valid
 * or does not pass the authentication match comparison.
 * 
 * @author Kevin Preece
 */
public class InvalidPassphraseException extends PasswordSafeException
{
	/**
	 * 
	 */
	public InvalidPassphraseException()
	{
		super();
	}

	/**
	 * @param message
	 */
	public InvalidPassphraseException(String message)
	{
		super(message);
	}

	/**
	 * @param message
	 * @param cause
	 */
	public InvalidPassphraseException(String message, Throwable cause)
	{
		super(message, cause);
	}

	/**
	 * @param cause
	 */
	public InvalidPassphraseException(Throwable cause)
	{
		super(cause);
	}
}
