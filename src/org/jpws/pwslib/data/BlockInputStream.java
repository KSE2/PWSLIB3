/*
 *  BlockInputStream in org.jpws.pwslib.data
 *  file: BlockInputStream.java
 * 
 *  Project PWSLIB2
 *  @author Wolfgang Keller
 *  Created 12.09.2006
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

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.StreamCorruptedException;

import org.jpws.pwslib.crypto.PwsCipher;
import org.jpws.pwslib.global.PwsChecksum;
import org.jpws.pwslib.global.Util;

/**
 * Package class to implement the <code>PwsBlockInputStream</code> interface. 
 * @since 2-0-0
 */
class BlockInputStream implements PwsBlockInputStream
{

   private PwsCipher cipher;
   private PwsChecksum hmac;
   private InputStream input;  // underlying encrypted input stream
   private byte[] nextBlock;   // decrypted next data block or null
   
   private int blocksize;      // cipher block size
   private int blockCount;     // blocks read so far

   /**
    * Creates a BlockInputStream from an input data stream and a cipher.
    * The BlockInputStream starts decrypting at the current read position
    * of the parameter input stream.
    * 
    * @param in input data stream
    * @param cipher <code>PwsCipher</code> used to decrypt the stream
    * @throws IOException if data cannot be read from the input steam
    * @throws StreamCorruptedException if there is not enough data available
    *         to read one block for decryption 
    */
   public BlockInputStream ( InputStream in, PwsCipher cipher ) throws IOException
   {
      this.cipher = cipher;
      this.blocksize = cipher.getBlockSize();
      this.input = in;
      try { readNextBlock(); }
      catch ( EOFException e )
      {
         throw new StreamCorruptedException( "unable to read first block" );
      }
   }
   
   private void readNextBlock () throws IOException
   {
      byte[] block;
      int readLen;
      
      nextBlock = null;
      block = new byte[ blocksize ];
      readLen = input.read( block );
      
      // regular end of file (blocking ok)
      if ( readLen == -1 )
         return;
      
      // irregular end of file (blocking false)
      if ( readLen < blocksize )
         throw new EOFException("illegal received block length: " + readLen );
      
      nextBlock = cipher.decrypt( block );
   } // readNextBlock
   
   public void close ()
   {
      if ( nextBlock != null )
          Util.destroyBytes(nextBlock);
      nextBlock = null;
      input = null;
   }

   public int getBlockSize ()
   {
      return blocksize;
   }

   public int getCount ()
   {
      return blockCount;
   }

   /** Resets this stream's block counter to 0. */
   public void resetCounter ()
   {
      blockCount = 0;
   }
   
   public boolean isAvailable ()
   {
      return nextBlock != null;
   }

   public byte[] peekBlock ()
   {
      return nextBlock != null ? (byte[])nextBlock.clone() : null;
   }
   
   public byte[] readBlock () throws IOException
   {
      byte[] block;
      
      block = null;
      if ( nextBlock != null )
      {
         block = nextBlock;
         readNextBlock();
         blockCount++;
      }
      else
         close();
      
      // update a cleartext stream checksum
      if ( hmac != null ) {
         hmac.update(block);
      }
      return block;
   }
   
   public byte[] readBlocks ( int blocks ) throws IOException
   {
      byte[] buffer, buf2;
      int length, i, len;
      
      length = blocks * blocksize;
      if ( blocks < 0 )
         throw new IllegalArgumentException( "invalid block request: " + blocks );

      buffer = new byte[ length ];

      // don't make an effort for 0 requests
      if ( length > 0 )
      {
         // utilise simpler readBlock method for one-block request
         if ( blocks == 1 )
            return readBlock();
         
         // end of stream reached
         if ( nextBlock == null )
         {
            close();
            return null;
         }
         
         // read remainder of data request from input 
         // (throws EOF if insufficient data supplied)
         len = length - blocksize;
         buf2 = new byte[ len ];
         i = input.read( buf2 );
         if ( i < len )
         {
            close(); 
            throw new EOFException("block length (remainder)");
         }
         
         // copy nextBlock into buffer
         System.arraycopy( nextBlock, 0, buffer, 0, blocksize );
         
         // decrypt and copy remainder buffer
         buf2 = cipher.decrypt( buf2 );
         System.arraycopy( buf2, 0, buffer, blocksize, len );
         Util.destroyBytes(buf2);

         // expunge copied "nextBlock"
         Util.destroyBytes(nextBlock);
         readNextBlock();
         blockCount += blocks;
      }
      
      // update a cleartext stream checksum
      if ( hmac != null ) {
         hmac.update(buffer);
      }
      return buffer;
   }

   public PwsChecksum getStreamHmac() {
      return hmac;
   }

   public void setStreamHmac(PwsChecksum hmac) {
      this.hmac = hmac;
   }
}