/*
 *  File: ByteArrayOutputStreamPws.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 26.07.2005
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

package org.jpws.pwslib.persist;

import java.io.ByteArrayOutputStream;

import org.jpws.pwslib.global.Util;

/**
 *  A <code>ByteArrayOutputStream</code> that is capable of erasing its
 *  internal byte buffer.
 */
public class ByteArrayOutputStreamPws extends ByteArrayOutputStream
{

/**
 * 
 */
public ByteArrayOutputStreamPws ()
{
   super();
}

/**
 * @param size
 */
public ByteArrayOutputStreamPws ( int size )
{
   super( size );
}

/** Erases the internal byte buffer and resets the object. */
public void clear ()
{
   Util.destroyBytes( this.buf );
   this.reset();
}

}
