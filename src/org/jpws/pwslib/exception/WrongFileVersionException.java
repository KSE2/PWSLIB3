/*
 *  File: WrongFileVersionException.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 17.09.2006
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
