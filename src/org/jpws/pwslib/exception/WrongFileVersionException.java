/*
 * $Id: WrongFileVersionException.java,v 1.1.1.1 2006/09/17 17:30:02 Besitzer Exp $
 * 
 * This file is provided under the standard terms of the Artistic Licence.  See the
 * LICENSE file that comes with this package for details.
 */
package org.jpws.pwslib.exception;

/**
 * Exception thrown to indicate that an incorrect file version was encountered .
 *
 */
public class WrongFileVersionException extends PasswordSafeException
{
	/**
	 * 
	 */
	public WrongFileVersionException()
	{
		super();
	}

	/**
	 * @param arg0
	 */
	public WrongFileVersionException( String arg0 )
	{
		super( arg0 );
	}

	/**
	 * @param arg0
	 */
	public WrongFileVersionException( Throwable arg0 )
	{
		super( arg0 );
	}

	/**
	 * @param arg0
	 * @param arg1
	 */
	public WrongFileVersionException( String arg0, Throwable arg1 )
	{
		super( arg0, arg1 );
	}
}
