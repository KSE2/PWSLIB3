/*
 *  File: NoSuchRecordException.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 02.09.2004
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
