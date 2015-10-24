/*
 *  V3_InputStream in org.jpws.pwslib.data
 *  file: V3_InputStream.java
 * 
 *  Project PWSLIB2
 *  @author Wolfgang Keller
 *  Created 26.09.2006
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

package org.jpws.pwslib.persist;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.jpws.pwslib.global.Global;
import org.jpws.pwslib.global.Util;

/**
 * PWS file format V3 specific input stream that terminates a wrapped 
 * input stream when it encounters the PWS3-EOF marker (cleartext
 * occurrence).
 * <p>Note: This has some unsupported operations.
 * 
 */
public class V3_InputStream extends FilterInputStream
{
   private byte[] hmac;
   private boolean eof;
   

public V3_InputStream ( InputStream in )
{
   super( in );
}

@Override
public int available () throws IOException
{
   return eof ? 0 : super.available();
}

@Override
public void close () throws IOException
{
   super.close();
   eof = true;
}

/**
 * Unsupported operation.
 */
@Override
public int read () throws IOException
{
   throw new UnsupportedOperationException();
}

/**
 * Reads up to <code>len</code> bytes of data from this input stream 
 * into an array of bytes. This method blocks until some input is 
 * available. 
 * <p>
 * @param      b     the buffer into which the data is read.
 * @param      off   the start offset of the data.
 * @param      len   the maximum number of bytes read.
 * @return     the total number of bytes read into the buffer, or
 *             <code>-1</code> if there is no more data because the end of
 *             the stream has been reached.
 * @exception  IOException  if an I/O error occurs.
 */
@Override
public int read ( byte[] b, int off, int len ) throws IOException
{
   byte[] buf;
   int i, rlen, le;
   
   // must be 16 block multiple
   if ( len % 16 > 0 )
      throw new IllegalArgumentException( "illegal data block length, must be multiple of 16" );
   
   // our homespun EOF condition
   if ( eof ) return -1;
   
   // read requested amount into buffer
   rlen = super.read( b, off, len );
   
   // control if V3-EOF marker is inside
   // if yes shorten resulting data block and mark stream for EOF
   for ( i = 0; i < rlen; i+=16 ) {

	   if ( Util.equalArrays( Global.FIELDSTREAM_ENDBLOCK_V3, b, off+i ) ) {
         // try read hmac from input if available
         buf = new byte[ 32 ];
         
         // what is left in read user buffer
         le = Math.min( rlen-i-16, 32 );
         System.arraycopy( b, off+i+16, buf, 0, le );
         
         // what we read extra
         if ( super.read( buf, le, 32-le ) == 32-le )
            hmac = buf;

         // modifications to represent EOF of this stream
         rlen = i == 0 ? -1 : i;
         eof = true;
         break;
      }
   }
   
   // return the (corrected) data size
// System.out.println( "-- read V3 input: " + rlen );    
   return rlen;
}

/** Whether EOF has been reached on this input stream. (Return value <b>true</b>
 * implies that a subsequent call to <i>read()</i> would return -1.)
 * 
 * @return boolean EOF state
 */
public boolean isEOF () 
{
   return eof;
}

/**
 * Unsupported operation.
 */
@Override
public long skip ( long n ) throws IOException
{
   throw new UnsupportedOperationException();
}

/**
 * Returns the hash function verification code encountered at the end
 * of stream and which serves to verify data integrity of the file. 
 * This information can only be available after the V3-inputstream has 
 * terminated. 
 *  
 * @return byte[] hmac of length 32 or <b>null</b> if this information is 
 *         unavailable
 */
public byte[] getHashMac()
{
   return hmac;
}

}
