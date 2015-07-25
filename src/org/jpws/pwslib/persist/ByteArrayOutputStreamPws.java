/*
 *  ByteArrayOutputStreamPws in org.jpws.pwslib.global
 *  file: ByteArrayOutputStreamPws.java
 * 
 *  Project JPasswords
 *  @author Wolfgang Keller
 *  Created 26.07.2005
 *  Version
 * 
 *  Copyright (c) 2005 by Wolfgang Keller, Munich, Germany
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
