/*
 *  File: InvalidPassphraseException.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 2005
 * 
 *  Copyright (c) 2005-2015 by Wolfgang Keller, Munich, Germany
 * 
 This program is copyright protected to the author(s) stated above. However, 
 you can use, redistribute and/or modify it for free under the terms of the 
 2-clause BSD-like license given in the document section of this project.  

 This program is distributed in the hope that it will be useful, but WITHOUT
 ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 FOR A PARTICULAR PURPOSE. See the license for more details.
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
