/*
 *  PwsBlockOutputStream in org.jpws.pwslib.data
 *  file: PwsBlockOutputStream.java
 * 
 *  Project PWSLIB2
 *  @author Wolfgang Keller
 *  Created 20.08.2006
 *  Version
 * 
 *  Copyright (c) 2006 by Wolfgang Keller, Munich, Germany
 * 
 This program is not freeware software but copyright protected to the author(s)
 stated above. However, you can use, redistribute and/or modify it under the terms 
 of the GNU General Public License as published by the Free Software Foundation, 
 version 2 of the License.

 This program is distributed in the hope that it will be useful, but WITHOUT
 ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

 You should have received a copy of the GNU General Public License along with
 this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 Place - Suite 330, Boston, MA 02111-1307, USA, or go to
 http://www.gnu.org/copyleft/gpl.html.
 */

package org.jpws.pwslib.data;

import java.io.IOException;

import org.jpws.pwslib.global.PwsChecksum;

/**
 * Interface defines a low-level read streaming device of data blocks
 * of a fixed length. Depending on the encryption technology used in the linked
 * PWS file, the size of atomic data blocks may vary. 
 * 
 * <p>A <code>PwsBlockInputStream</code> always refers to a decryption 
 * process executed on a source PWS file. The blocks readable to the user
 * are the complete sequence of decrypted data segments as defined by the 
 * underlying file cipher, in the order as they are encountered in the source.
 * No interpretation or modification is performed on these data blocks by the
 * streaming instance.
 *  
 */

public interface PwsBlockInputStream
{

/**
 * Whether there is more data to be read from this stream.
 */
public boolean isAvailable ();

/** 
 * The number of blocks already read from this input stream.
 *  
 * @return int number of blocks starting from 0
 */
public int getCount ();

/**
 * The data block size of this stream.
 * 
 * @return int block size
 */
public int getBlockSize ();

/**
 * Reads the next block of decrypted data from this input stream. 
 * 
 * @return data block or <b>null</b> if the end of the stream has been reached
 * 
 * @throws java.io.EOFException if the file length is irregular (blocking error)              
 * @throws java.io.IOException if an IO error occurs              
 */
public byte[] readBlock () throws IOException;

/**
 * Reads a specified number of blocks from this input stream.
 * (Note: If <code>EOFException</code> is thrown, the stream
 * has reached its end but a number of blocks read by this
 * method are lost for the user. Hence requested blocks should 
 * belong to a single semantical unit.)
 *  
 * @param blocks int number of data blocks to be read 
 * @return decrypted data block of size <code>blocks * getBlockSize()</code>
 *         or <b>null</b> if there is no more data available
 * @throws java.io.EOFException if the remaining file length is insufficient
 *         for the requested data size              
 * @throws IOException
 */
public byte[] readBlocks ( int blocks ) throws IOException;

/**
 * Reads the next available block from this stream without progressing
 * reading from the source. Repeated calls to this method will render
 * the same logical block (although not the same object).
 * 
 * @return byte[] next block of this stream or <b>null</b> if unavailable
 */
public byte[] peekBlock ();

/**
 * Closes this input stream. After close no more data can be read from
 * this stream.
 */
public void close ();

/** Returns the checksum object that summarises all read cleartext data
 * through this block stream.
 *  
 * @return <code>PwsChecksum</code>
 */
public PwsChecksum getStreamHmac ();

/** Sets the operative checksum object for summarising read cleartext data
 * of this block stream. 
 * 
 * @param hmac <code>PwsChecksum</code>
 */
public void setStreamHmac ( PwsChecksum hmac );

}
