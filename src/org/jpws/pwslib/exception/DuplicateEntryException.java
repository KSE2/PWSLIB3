/*
 *  DuplicateEntryException in org.jpws.pwslib.exception
 *  file: DuplicateEntryException.java
 * 
 *  Project JPasswords
 *  @author Wolfgang Keller
 *  Created 01.09.2004
 *  Version
 */
package org.jpws.pwslib.exception;

/**
 *  Thrown to indicate an illegal attempt to insert an entry
 *  into a list which conflicts with uniqueness rules on the entry's
 *  value.
 */
public class DuplicateEntryException extends PasswordSafeException
{

/**
 * 
 */
public DuplicateEntryException ()
{
   super();
}

/**
 * @param arg0
 */
public DuplicateEntryException ( String arg0 )
{
   super( arg0 );
}

/**
 * @param arg0
 */
public DuplicateEntryException ( Throwable arg0 )
{
   super( arg0 );
}

/**
 * @param arg0
 * @param arg1
 */
public DuplicateEntryException ( String arg0, Throwable arg1 )
{
   super( arg0, arg1 );
}

}
