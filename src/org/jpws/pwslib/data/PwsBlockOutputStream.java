/*
 *  File: PwsBlockOutputStream.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 20.08.2006
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

import java.io.IOException;

/**
 * Interface defines a low-level write streaming device for data blocks
 * of a fixed length. Depending on the technology used in the linked
 * PWS file, blocksize may vary. 
 * 
 * <p>A <code>PwsBlockOutputStream</code> always refers to an encryption 
 * process executed for a target PWS file. The blocks written are the
 * data segments defined by the underlying encryption algorithm valid for
 * a target PWS file. 
 */

public interface PwsBlockOutputStream
{

/** 
 * The number of written blocks in this output stream.
 *  
 * @return int number of blocks (0 means new stream)
 */
public int getCount ();

/**
 * Whether this stream is closed.
 */
public boolean isClosed ();

/**
 * The data blocksize of this stream.
 */
public int getBlockSize ();

/** Accepts a cleartext data block and writes it encrypted to
 * the underlying output stream. (Parameter data not altered.)
 * If the given block is shorter than an integer multiple
 * of the stream's blocksize, sufficient zero bytes are appended
 * to the user data to form a block of required length. 
 * 
 * @param data byte[] cleartext data
 * @throws IOException
 */ 
public void writeBlocks ( byte[] data ) throws IOException;

/** Accepts a cleartext data block and writes it encrypted to
 * the underlying output stream. (Parameter data not altered.)
 * If the given data segment is shorter than an integer multiple
 * of the stream's blocksize, sufficient zero bytes are appended
 * to the user data to form a block of required length. 
 * 
 * @param data byte[] cleartext data buffer
 * @param offset int, start offset in buffer
 * @param length int, length of data segment to write
 * @throws IOException
 */ 
public void writeBlocks ( byte[] data, int offset, int length ) throws IOException;

/**
 * Closes this output stream and writes any remaining data to the 
 * underlying data stream. After close no more data may be written to
 * this stream. Does not close the underlying output stream!
 */
public void close () throws IOException;


}
