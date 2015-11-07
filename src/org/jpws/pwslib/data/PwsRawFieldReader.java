/*
 *  File: PwsRawFieldReader.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 25.10.2006
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

package org.jpws.pwslib.data;

import java.util.Iterator;


/**
 * Interface extending an iterator over {@link PwsRawField} objects
 * decrypted from the persistent state of a PWS file. 
 * 
 * <p>The <code>Iterator</code> interface is extended by a
 * close operation and a blocksize. This reader returns the results
 * from analysing a data stream from a persistent state of a PWS file 
 * and renders elements of type <code>PwsRawField</code> in the 
 * order as they are encountered in the source.  
 * 
 * <p>Closing the reader is possible to inform the object that
 * no more input is needed. The reader will then behave
 * as if the end of the stream were reached. (Closing is
 * automatically performed when the last data element of
 * the file was read from the reader.) The close operation
 * does, however, not close an underlying input stream.
 * 
 * @see PwsFileInputSocket
 */
public interface PwsRawFieldReader extends Iterator<PwsRawField>
{

/** The blocksize of the underlying cryptographical cipher. */
public abstract int getBlocksize ();

/** Closes this field reader (but not the underlying blockstream
 *  or underlying inputstream). 
 */
public abstract void close ();

public abstract boolean hasNext ();

/** Returns the next element of type <code>PwsRawField</code>.
 *  If the end of the field stream is reached or this stream
 *  has been closed, a <code>NoSuchElementException</code> is thrown. 
 */
public abstract PwsRawField next ();

/** Remove does nothing. 
 */
public abstract void remove ();

}