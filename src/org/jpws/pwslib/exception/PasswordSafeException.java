/*
 *  PasswordSafeException in org.jpws.pwslib.exception
 *  file: PasswordSafeException.java
 * 
 *  Project JPasswords
 *  @author Wolfgang Keller
 *  Created 29.08.2004
 *  Version
 */
package org.jpws.pwslib.exception;

/**
 *  Super class for all type specific exceptions of the PWS library.
 */
public class PasswordSafeException extends Exception
{

/**
 * 
 */
public PasswordSafeException ()
{
   super();
}

/**
 * @param arg0
 */
public PasswordSafeException ( String arg0 )
{
   super( arg0 );
}

/**
 * @param arg0
 */
public PasswordSafeException ( Throwable arg0 )
{
   super( arg0 );
}

/**
 * @param arg0
 * @param arg1
 */
public PasswordSafeException ( String arg0, Throwable arg1 )
{
   super( arg0, arg1 );
}

}
