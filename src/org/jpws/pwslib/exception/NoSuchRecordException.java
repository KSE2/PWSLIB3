/*
 *  NoSuchRecordException in org.jpws.pwslib.exception
 *  file: NoSuchRecordException.java
 * 
 *  Project JPasswords
 *  @author Wolfgang Keller
 *  Created 02.09.2004
 *  Version
 */
package org.jpws.pwslib.exception;

/**
 *  <p>Thrown to indicate that an operation on a requested record
 *  cannot be performed because such a record does not exist in the
 *  context of the executing object. 
 */
public class NoSuchRecordException extends PasswordSafeException
{

/**
 * 
 */
public NoSuchRecordException ()
{
   super();
}

/**
 * @param arg0
 */
public NoSuchRecordException ( String arg0 )
{
   super( arg0 );
}

/**
 * @param arg0
 */
public NoSuchRecordException ( Throwable arg0 )
{
   super( arg0 );
}

/**
 * @param arg0
 * @param arg1
 */
public NoSuchRecordException ( String arg0, Throwable arg1 )
{
   super( arg0, arg1 );
}

}
