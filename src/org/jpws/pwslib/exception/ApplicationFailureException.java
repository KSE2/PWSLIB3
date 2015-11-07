/*
 *  File: ApplicationFailureException.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 29.08.2004
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
