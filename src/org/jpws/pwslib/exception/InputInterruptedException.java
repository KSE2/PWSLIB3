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

import java.io.IOException;

/**
 *  Thrown to indicate an illegal attempt to insert an entry
 *  into a list which conflicts with uniqueness rules on the entry's
 *  value.
 *  @since 0-3-0
 */
public class InputInterruptedException extends IOException
{

/**
 * 
 */
public InputInterruptedException ()
{
   super();
}

/**
 * @param arg0
 */
public InputInterruptedException ( String arg0 )
{
   super( arg0 );
}


}
