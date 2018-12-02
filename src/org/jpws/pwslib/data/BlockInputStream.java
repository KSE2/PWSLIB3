/*
 *  File: BlockInputStream.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 12.09.2006
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

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.StreamCorruptedException;

import org.jpws.pwslib.crypto.PwsCipher;
import org.jpws.pwslib.global.Util;

/**
 * Package class to implement the <code>PwsBlockInputStream</code> interface. 
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
    * @param in <code>InputStream</code> input data stream
    * @param cipher <code>PwsCipher</code> used to decrypt the stream
    * @throws IOException if data cannot be read from the input steam
    * @throws StreamCorruptedException if there is not enough data available
    *         to read one block for decryption 
    */
   public BlockInputStream (InputStream in, PwsCipher cipher) throws IOException
   {
      this.cipher = cipher;
      this.blocksize = cipher.getBlockSize();
      this.input = in;
      try { 
    	  readNextBlock(); 
      } catch ( EOFException e ) {
         throw new StreamCorruptedException( "unable to read first block" );
      }
   }
   
   private void readNextBlock () throws IOException
   {
      nextBlock = null;
      byte[] block = new byte[ blocksize ];
      int readLen = input.read( block );
      
      // regular end of file (blocking ok)
      if ( readLen == -1 ) return;
      
      // irregular end of file (blocking false)
      if ( readLen < blocksize ) {
         throw new EOFException("illegal read block length: " + readLen );
      }
      
      nextBlock = cipher.decrypt( block );
   } // readNextBlock
   
   @Override
   public void close ()
   {
      if ( nextBlock != null ) {
          Util.destroyBytes(nextBlock);
      }
      nextBlock = null;
      input = null;
   }

   @Override
   public int getBlockSize ()
   {
      return blocksize;
   }

   @Override
   public int getCount ()
   {
      return blockCount;
   }

   /** Resets this stream's block counter to 0. */
   public void resetCounter ()
   {
      blockCount = 0;
   }
   
   @Override
   public boolean isAvailable ()
   {
      return nextBlock != null;
   }

   @Override
   public byte[] peekBlock ()
   {
      return nextBlock != null ? (byte[])nextBlock.clone() : null;
   }
   
   @Override
   public byte[] readBlock () throws IOException
   {
      byte[] block = null;
      if ( nextBlock != null ) {
         block = nextBlock;
         readNextBlock();
         blockCount++;
      } else {
         close();
      }
      
      // update a cleartext stream checksum
      if ( hmac != null ) {
         hmac.update(block);
      }
      return block;
   }
   
   @Override
   public byte[] readBlocks ( int blocks ) throws IOException
   {
      byte[] buffer, buf2;
      int length, i, len;
      
      if ( blocks < 0 ) 
         throw new IllegalArgumentException( "invalid block request: " + blocks );

      length = blocks * blocksize;
      buffer = new byte[ length ];

      // don't make an effort for 0 requests
      if ( length > 0 ) {
         // utilise simpler readBlock method for one-block request
         if ( blocks == 1 ) {
            return readBlock();
         }
         
         // end of stream reached
         if ( nextBlock == null ) {
            close();
            return null;
         }
         
         // read remainder of data request from input 
         // (throws EOF if insufficient data supplied)
         len = length - blocksize;
         buf2 = new byte[ len ];
         i = input.read( buf2 );
         if ( i < len ) {
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

   @Override
   public PwsChecksum getStreamHmac () 
   {
      return hmac;
   }

   @Override
   public void setStreamHmac (PwsChecksum hmac) 
   {
      this.hmac = hmac;
   }
}