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

import kse.utilclass.misc.Util;

/**
 * Package class to implement the <code>PwsBlockInputStream</code> interface.
 * Note that the input-stream as parameter to this stream is not closed
 * when this stream gets closed.
 */
class BlockInputStream implements PwsBlockInputStream
{
   private PwsCipher cipher;
   private PwsChecksum hmac;
   private InputStream input;  // underlying encrypted input stream
   
   private byte[] blockBuffer;
   private int bufferPointer;
   private int bufferTop;
   private byte[] nextBlock;   // decrypted next data block or null
   private byte[] outBlock;    // decrypted return block or null
   
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
   public BlockInputStream (InputStream in, PwsCipher cipher, int bufferFactor) 
		   throws IOException {
	  if ( in == null )
		  throw new IllegalArgumentException("input-stream is null");
	  if ( bufferFactor < 1 )
		  throw new IllegalArgumentException("illegal buffer factor");
   
	  // prepare cipher and file block buffering
      this.cipher = cipher;
      blocksize = cipher.getBlockSize();
      input = in;
      blockBuffer = new byte[ bufferFactor * cipher.getBlockSize() ];
      bufferPointer = blockBuffer.length;
      
      try { 
    	  readNextBlock(); 
      } catch ( EOFException e ) {
         throw new StreamCorruptedException( "unable to read first block" );
      }
   }
   
   private void readNextBlock () throws IOException {
      // read and decrypt block buffer (if top is reached by polling)
      if ( bufferTop <= bufferPointer ) {
    	  int readLen = input.read( blockBuffer );
      
    	  // regular end of file (blocking ok)
    	  if ( readLen == -1 ) {
    		  nextBlock = null;
    		  return;
    	  }
      
    	  // irregular end of file (blocking false)
    	  if ( readLen % blocksize != 0 ) {
    		  close();
    		  throw new EOFException("illegal read block length: " + readLen );
    	  }
      
    	  // decrypt block buffer
    	  cipher.decrypt( blockBuffer, 0, blockBuffer, 0, readLen );
    	  bufferTop = readLen;
    	  bufferPointer = 0;
    	  
    	  // lazily create next-block buffer
    	  if ( nextBlock == null && readLen > 0 ) {
    		  nextBlock = new byte[ blocksize ];
    		  outBlock = new byte[ blocksize ];
    	  }
      }
    	  
	  // read next block
	  System.arraycopy(blockBuffer, bufferPointer, nextBlock, 0, blocksize);
	  bufferPointer += blocksize;
   } // readNextBlock
   
   @Override
   public void close () {
      if ( nextBlock != null ) {
          Util.destroy(nextBlock);
      }
      if ( outBlock != null ) {
          Util.destroy(outBlock);
      }
      if ( blockBuffer != null ) {
    	  Util.destroy(blockBuffer);
      }
      nextBlock = null;
      blockBuffer = null;
      input = null;
   }

   @Override
   public int getBlockSize () {
      return blocksize;
   }

   @Override
   public int getCount () {
      return blockCount;
   }

   /** Resets this stream's block counter to 0. */
   public void resetCounter () {
      blockCount = 0;
   }
   
   @Override
   public boolean isAvailable () {
      return nextBlock != null;
   }

   @Override
   public byte[] peekBlock () {
	  return nextBlock;
//      return nextBlock != null ? (byte[])nextBlock.clone() : null;
   }
   
   @Override
   public byte[] readBlock () throws IOException {
      if ( nextBlock != null ) {
         System.arraycopy(nextBlock, 0, outBlock, 0, blocksize);
         readNextBlock();
         blockCount++;
      } else {
         close();
         return null;
      }
      
      // update a clear-text stream checksum
      if ( hmac != null ) {
         hmac.update(outBlock);
      }
      return outBlock;
   }
   
   @Override
   public byte[] readBlocks ( int blocks ) throws IOException {
      if ( blocks < 0 ) 
         throw new IllegalArgumentException( "invalid block request: " + blocks );

      int length = blocks * blocksize;
      byte[] buffer = new byte[ length ];
      try {
    	  writeBlocks(buffer, 0, length);
      } catch (IOException e) {
    	  close();
    	  throw e;
      }
      return buffer;
   }

   @Override
   public int writeBlocks ( byte[] buffer, int start, int length ) throws IOException {
      if ( length < 0 ) 
         throw new IllegalArgumentException( "invalid length request: " + length );

      int blocks = 0;

      if ( length > 0 ) {
		  // read series of blocks
		  int written = 0;
		  while ( written < length ) { 
			 byte[] block = readBlock();
			 if ( block == null ) {
				 throw new EOFException("end of block stream");
			 }
			 int len = Math.min(length-written, blocksize);
			 System.arraycopy(block, 0, buffer, start + blocks * blocksize, len);
			 written += len;
			 blocks++;
	      }
      }
      return blocks;
   }

   @Override
   public PwsChecksum getStreamHmac () {
      return hmac;
   }

   @Override
   public void setStreamHmac (PwsChecksum hmac) {
      this.hmac = hmac;
   }
}