/*
 *  File: PwsFileOutputSocket.java
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
import java.io.OutputStream;

import org.jpws.pwslib.crypto.PwsCipher;
import org.jpws.pwslib.global.Global;
import org.jpws.pwslib.global.UUID;

import kse.utilclass.misc.Util;
import kse.utilclass.misc.Log;


/**
 *  PwsFileOutputSocket organises data output to a single
 *  underlying data stream for the purposes of creating a persistent state
 *  of a PWS file. 
 *  This includes realization of different file format versions and
 *  makes these differences opaque to the user. It also fully organises
 *  creation of an encryption cipher and its application to a 
 *  block-segmented data stream. 
 *  
 *  @see org.jpws.pwslib.data.PwsBlockOutputStream
 *  @see org.jpws.pwslib.data.PwsRawFieldWriter
 */

public class PwsFileOutputSocket {
	
   private OutputStream output;
   private PwsCipher cipher;
   private BlockWriter writer;
   private PwsPassphrase key;
   private HeaderFieldList headerFields;
   private UUID fileID;
   private PwsChecksum hmac;
   
   private int version;
   private int iterations = 2048;
   private int cipherKeyLength = 256;
   
   
   /**
 * Creates an output socket with an empty header field list. (Essential header
 * fields will be created with default values where necessary.)
 * 
 * @param output the target output stream
 * @param key <code>PwsPassphrase</code> user key for the encryption cipher  
 * @param fileVersion file format version to be created (values of class <code>Global</code>)
 */
public PwsFileOutputSocket ( OutputStream output, PwsPassphrase key, int fileVersion ) {
   this( output, key, null, fileVersion );
}  // constructor

/**
 * Creates an output socket with full settings, including optional file 
 * generic header data.
 * 
 * @param output the target output stream
 * @param key <code>PwsPassphrase</code> user key for the encryption cipher 
 *        (file access key)
 * @param fileVersion file format version to be created (values of class 
 *        <code>Global</code>)
 * @param headerFields file generic header data in a <code>HeaderFieldList</code>
 *        (e.g. contains user options, file-UUID, etc.); may be <b>null</b> 
 */
public PwsFileOutputSocket ( OutputStream output, 
                             PwsPassphrase key, 
                             HeaderFieldList headerFields, 
                             int fileVersion 
                            )
{
   if ( output == null | key == null )
      throw new NullPointerException();
   
   this.output = output;
   this.key = (PwsPassphrase)key.clone();
   this.version = fileVersion;
   this.headerFields = headerFields;
}  // constructor

/**
 * Creates an output socket for the latest file format version (V3) and optional
 * file generic header data.
 * 
 * @param output the target output stream
 * @param key <code>PwsPassphrase</code> user key for the encryption cipher (file access key)
 * @param headerFields file generic header data in a <code>HeaderFieldList</code>
 *        (e.g. contains user options, file-UUID, etc.); may be <b>null</b> 
 */
public PwsFileOutputSocket ( OutputStream output, 
                             PwsPassphrase key, 
                             HeaderFieldList headerFields 
                            )
{
   this( output, key, headerFields, Global.FILEVERSION_LATEST_MAJOR );
}  // constructor

/** Sets the security level for the encryption in measure of the cipher
 * key length in bits. This can be one of [64, 128, 192, 256]. The
 * default value is 256 (full security).
 * <p>NOTE: This must be called before 'getBlockOutputStrean()' is called
 * otherwise it has no effect.
 * 
 * @param bits int key length
 */
public void setKeySecurity (int bits) {
	if (cipher != null) return;
	if (bits == 256 || bits == 128 || bits == 192 || bits == 64) {
		cipherKeyLength = bits;
	} else {
		throw new IllegalArgumentException("illegal ley-length value: " + bits);
	}
}

public int getKeySecurity () {return cipherKeyLength;}

/**
 * Destroys all sensible data in this object and renders it unusable.
 * (This can be called without prior call to <code>close()</code>.)
 */
public void destroy () {
   output = null;
   cipher = null;
   key = null;
}

/**
 * Closes this socket but not the underlying output stream.
 * (Includes a call to <code>destroy()</code>.)
 * 
 * @throws IOException
 */
public void close ()  throws IOException {
   if ( writer != null ) {
      writer.close();
   }

   destroy();
   Log.debug( 2, "(PwsFileOutputSocket) closing output blockstream, HMAC = " + 
         (hmac == null? "void" : Util.bytesToHex( hmac.digest() )));
}

private void initOutput () throws IOException {
   // create file header
   Log.log( 5, "(PwsFileOutputSocket) initOutput, 0" );
   switch ( version ) {
   case Global.FILEVERSION_3:
	  PwsFileHeaderV3 hd3 = new PwsFileHeaderV3( headerFields );
      Log.log( 5, "(PwsFileOutputSocket) initOutput, 1" );
      hd3.setIterations( iterations );
      hd3.setKeySecurity(cipherKeyLength);
      Log.log( 5, "(PwsFileOutputSocket) initOutput, 2" );
      fileID = hd3.getFileID();
      cipher = hd3.save( output, key );
      hmac = hd3.getWriteHmac();
      break;
      
   default: throw new IllegalArgumentException( "unknown file format version: " + version );   
   }
}

/**
 * Returns the file identifier UUID or <b>null</b> if it is not
 * available. (Available only for V3 files)
 * 
 * @return <code>UUID</code> file identifier value
 */
public UUID getFileID () {return fileID;}

/** The number of security iterations of key calculation
 * during file authentication or file-save.
 * 
 * @return int number of calculation iterations
 */
public int getIterations () {return iterations;}

/** Sets the number of security loops of key calculation
 * occurring during file authentication or file-save.
 * The parameter value is corrected to comply to a minimum of 2048.  
 * 
 * @param iterations int number of calculation loops
 */
public void setIterations ( int iterations ) {
	if (cipher == null) {
		this.iterations = Math.max( 2048, iterations );
	}
}

/**
 * Returns an object specialised to write PWS raw fields to the underlying 
 * data stream. Calling this will initially create the header of the new
 * PWS file in the output stream.  
 *  
 * @return <code>RawFieldWriter</code>
 * @throws IOException
 */
public PwsRawFieldWriter getRawFieldWriter () throws IOException {
   return (PwsRawFieldWriter)getBlockOutputStream();
}


/**
 * Returns a data-block oriented output stream designed to realise the contents
 * of a PWS data file to the underlying output stream. Calling this will 
 * initially create the header of the new PWS file in the output stream.  
 *  
 * @return <code>PwsBlockOutputStream</code>
 * @throws IOException
 */
public PwsBlockOutputStream getBlockOutputStream () throws IOException {
   if ( writer != null )
      throw new IllegalStateException( "duplicate output stream" );
   
   Log.log( 5, "(PwsFileOutputSocket) getBlockOutputStream" );
   initOutput();
   writer = new BlockWriter( output, cipher, version );
   return writer;
}

/**
 * Returns the blocksize used by this socket or 0 if this socket has not 
 * been opened. The socket is opened by invoking the block-output-stream
 * or the raw-field-writer.
 * 
 * @return int cipher blocksize or 0
 */
public int getBlocksize () {
   return cipher != null ? cipher.getBlockSize() : 0;
}

//  ***************  INNER CLASSES  *****************

/**
 *  <p>Writing instrument that sequentially writes encrypted BLOCKs
 *  to a database output stream. Also writes the next aggregation
 *  of BLOCKs: DATAFIELDS as handed over in <code>RawField</code> objects. 
 */
private class BlockWriter implements PwsBlockOutputStream, PwsRawFieldWriter
{
   OutputStream out;
   PwsCipher cipher;
   int blocksize;
   int blockCount;
   int fileVersion;
   
   /** Constructs a BlockWriter from an output stream and an encryption
    *  cipher.
    * 
    * @param output stream where blocks of data will be written to
    * @param cipher cipher by which blocks will be encrypted
    */
   public BlockWriter ( OutputStream output, PwsCipher cipher, int format ) {
      if ( output == null | cipher == null )
         throw new NullPointerException();
      
      out = output;
      this.cipher = cipher;
      blocksize = cipher.getBlockSize();
      fileVersion = format;
   }
   
   @Override
   public int getCount () {
      return blockCount;
   }

   @Override
   public int getFormat () {
      return fileVersion;
   }
   
   @Override
   public int getBlockSize () {
      return blocksize;
   }

   @Override
   public boolean isClosed () {
      return out == null;
   }
   
   @Override
   public void writeBlocks ( byte[] data, int offset, int length ) throws IOException {
      if ( out == null )
         throw new IllegalStateException( "outputstream closed" );
      
      // prepare data (ensure correct block length)
      byte[] buf2;
      int blocks = length / blocksize;
      if ( length - blocks * blocksize > 0 ) {
    	 // "enrich" block space 
         blocks++;
         byte[] buf = Util.arraycopy( data, offset, blocks * blocksize );
         buf2 = cipher.encrypt( buf );
         hmac.update(buf);
         Util.destroy(buf);
      } else  {
    	 // fitting block space 
         buf2 = cipher.encrypt( data, offset, length );
         hmac.update(data, offset, length);
      }

      // create and write encrypted data
      out.write( buf2 );
      blockCount += blocks;
   }

   @Override
   public void writeBlocks ( byte[] data ) throws IOException {
      if ( out == null )
         throw new IllegalStateException( "outputstream closed" );
      
      writeBlocks( data, 0, data.length );
   }
   
   @Override
   public void writeRawField ( PwsRawField rawField ) throws IOException {
      rawField.writeEncrypted( out, cipher, fileVersion, hmac );
   }  

   @Override
   public void close () throws IOException {
      if ( fileVersion == Global.FILEVERSION_3 & out != null ) {
         // write V3 appendix
         out.write( Global.FIELDSTREAM_ENDBLOCK_V3 );
         out.write( hmac.digest() );
      }
      out = null;
   }

//   public PwsBlockOutputStream getBlockStream ()
//   {
//      return this;
//   }
}  // class BlockWriter

}
