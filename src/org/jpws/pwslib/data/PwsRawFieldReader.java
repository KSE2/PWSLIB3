/*
 *  PwsRawFieldReader in org.jpws.pwslib.data
 *  file: PwsRawFieldReader.java
 * 
 *  Project PWSLIB2
 *  @author Wolfgang Keller
 *  Created 25.10.2006
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
 * does, however, not close the underlying input stream.
 * 
 * @see PwsFileInputSocket
 * @since 2-0-0
 */
public interface PwsRawFieldReader extends Iterator
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
public abstract Object next ();

public abstract void remove ();

}