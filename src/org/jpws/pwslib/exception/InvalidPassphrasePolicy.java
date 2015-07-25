/*
 * $Id: InvalidPassphrasePolicy.java,v 1.1.1.1 2006/09/17 17:30:02 Besitzer Exp $
 * 
 * This file is provided under the standard terms of the Artistic Licence.  See the
 * LICENSE file that comes with this package for details.
 */
package org.jpws.pwslib.exception;

/**
 * An exception thrown to indicate that a passphrase policy setting is incorrect.
 *
 */
public class InvalidPassphrasePolicy extends PasswordSafeException
{
	/**
	 * 
	 */
	public InvalidPassphrasePolicy()
	{
		super();
	}

	/**
	 * @param arg0
	 */
	public InvalidPassphrasePolicy( String arg0 )
	{
		super( arg0 );
	}

	/**
	 * @param arg0
	 */
	public InvalidPassphrasePolicy( Throwable arg0 )
	{
		super( arg0 );
	}

	/**
	 * @param arg0
	 * @param arg1
	 */
	public InvalidPassphrasePolicy( String arg0, Throwable arg1 )
	{
		super( arg0, arg1 );
	}
}
