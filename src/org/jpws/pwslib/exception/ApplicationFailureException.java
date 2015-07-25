/*
 *  ApplicationFailureException in org.jpws.pwslib.exception
 *  file: ApplicationFailureException.java
 * 
 *  Project JPasswords
 *  @author Wolfgang Keller
 *  Created 29.08.2004
 *  Version
 */
package org.jpws.pwslib.exception;

import java.io.IOException;

/**
 * Exception thrown to indicate that an application context does not or can not 
 * render the IO resource that was requested from it.  
 */
public class ApplicationFailureException extends IOException
{

/**
 * 
 */
public ApplicationFailureException ()
{
   super();
}

/**
 * @param arg0
 */
public ApplicationFailureException ( String arg0 )
{
   super( arg0 );
}


}
