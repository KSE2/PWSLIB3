/*
 *  PwsFile in org.jpws.pwslib.data
 *  file: PwsFile.java
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
import java.io.OutputStream;

import org.jpws.pwslib.crypto.PwsCipher;
import org.jpws.pwslib.global.Global;
import org.jpws.pwslib.global.Log;
import org.jpws.pwslib.global.PwsChecksum;
import org.jpws.pwslib.global.UUID;
import org.jpws.pwslib.global.Util;


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
 *  @see org.jpws.pwslib.data.PwsFileOutputSocket.RawFieldWriter
 */

public class PwsFileOutputSocket
{
   private OutputStream output;
   private PwsCipher cipher;
   private BlockWriter writer;
   private PwsPassphrase key;
   private HeaderFieldList headerFields;
   private UUID fileID;
   private PwsChecksum hmac;
   
   private int version;
   private int iterations = 2048;
   
   
   /**
    * Interface defining a device designed to write objects of type {@link
    * PwsRawField} to an encrypted output stream. This writer organises
    * the appropriate block stream of the cipher depending on previously 
    * defined file parameters.  
    * 
    * <p>Closing the writer is possible to avoid further use, but does not
    * close the underlying data stream.
    * 
    */
   public interface RawFieldWriter 
   {

   /**
    * Closes this writer and flushes data. Does not close the underlying
    * output stream. 
    */
   public void close () throws IOException;

   /** The blocksize of the underlying encryption cipher. 
    */
   public int getBlockSize ();

   /** The file format version for which this writer was defined. 
    * 
    * @return int format version
    */
   public int getFormat ();
   
   
   /**
    * Writes a single raw field to the underlying (encrypted) output stream.
    * 
    * @param rawField <code>PwsRawField</code>
    * @throws IOException
    */
   public void writeRawField ( PwsRawField rawField ) throws IOException;

   /** 
    * The number of written blocks in the underlying output stream.
    *  
    * @return int number of blocks (0 means new stream)
    */
   public int getCount ();
   
//   /** Returns the blockstream on which this writer operates.
//    * 
//    * @return <code>PwsBlockOutputStream</code>
//    */
//   public PwsBlockOutputStream getBlockStream ();
   }  // interface RawFieldWriter


   
/**
 * Creates an output socket with an empty header field list. (Essential header
 * fields will be created with default values where necessary.)
 * 
 * @param output the target output stream
 * @param key <code>PwsPassphrase</code> secret key for the encryption cipher  
 * @param fileVersion file format version to be created (values of class <code>Global</code>)
 */
public PwsFileOutputSocket ( OutputStream output, PwsPassphrase key, int fileVersion )
{
   this( output, key, null, fileVersion );
}  // constructor

/**
 * Creates an output socket with full settings, including optional file generic header data.
 * 
 * @param output the target output stream
 * @param key <code>PwsPassphrase</code> secret key for the encryption cipher (file access key)
 * @param fileVersion file format version to be created (values of class <code>Global</code>)
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
 * @param key <code>PwsPassphrase</code> secret key for the encryption cipher (file access key)
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

/**
 * Destroys all sensible data in this object and renders it unusable.
 * (This can be called without prior call to <code>close()</code>.)
 */
public void destroy ()
{
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
public void close ()  throws IOException
{
   if ( writer != null ) {
      writer.close();
   }

   destroy();
   Log.debug( 2, "(PwsFileOutputSocket) closing output blockstream, HMAC = " + 
         (hmac == null? "void" : Util.bytesToHex( hmac.digest() )));
}

private void initOutput () throws IOException
{
   // create file header
   Log.log( 5, "(PwsFileOutputSocket) initOutput, 0" );
   switch ( version )
   {
   case Global.FILEVERSION_1:
      cipher = new PwsFileHeaderV1().save( output, key );
      break;

   case Global.FILEVERSION_2:
      String options = headerFields == null ? "" : headerFields.getStringValue(
    		           PwsFileHeaderV3.JPWS_OPTIONS_TYPE );
      cipher = new PwsFileHeaderV2().save( output, key, options );
      break;
      
   case Global.FILEVERSION_3:
	   PwsFileHeaderV3 hd3 = new PwsFileHeaderV3( headerFields );
      Log.log( 5, "(PwsFileOutputSocket) initOutput, 1" );
      hd3.setIterations( iterations );
      Log.log( 5, "(PwsFileOutputSocket) initOutput, 2" );
      fileID = hd3.getFileID();
      cipher = hd3.save( output, key );
      hmac = hd3.getWriteHmac();
      break;
      
   default: throw new IllegalArgumentException( "unknown file format version: " + version );   
   }
}  // initOutput

/**
 * Returns the file identifier UUID or <b>null</b> if it is not
 * available. (Available only for V3 files)
 * 
 * @return <code>UUID</code> file identifier value
 */
public UUID getFileID ()
{
   return fileID;
}

/** The number of security iterations of key calculation
 * during file authentication or file-save.
 * 
 * @return int number of calculation iterations
 */
public int getIterations ()
{
   return iterations;
}

/** Sets the number of security loops of key calculation
 * occurring during file authentication or file-save.
 * The parameter value is corrected to comply to a minimum of 2048.  
 * 
 * @param iterations int number of calculation loops
 */
public void setIterations ( int iterations )
{
   this.iterations = Math.max( 2048, iterations );
}

/**
 * Returns an object specialised to write PWS raw fields to the underlying 
 * data stream. Calling this will initially create the header of the new
 * PWS file in the output stream.  
 *  
 * @return <code>RawFieldWriter</code>
 * @throws IOException
 */
public RawFieldWriter getRawFieldWriter () throws IOException
{
   return (RawFieldWriter)getBlockOutputStream();
}


/**
 * Returns a data-block oriented output stream designed to realise the contents
 * of a PWS data file to the underlying output stream. Calling this will 
 * initially create the header of the new PWS file in the output stream.  
 *  
 * @return <code>PwsBlockOutputStream</code>
 * @throws IOException
 */
public PwsBlockOutputStream getBlockOutputStream () throws IOException
{
   if ( writer != null )
      throw new IllegalStateException( "output stream in use or consumed" );
   
   Log.log( 5, "(PwsFileOutputSocket) getBlockOutputStream" );
   initOutput();
   writer = new BlockWriter( output, cipher, version );
   return writer;
}


//  ***************  INNER CLASSES  *****************

/**
 *  <p>Writing instrument that sequentially writes encrypted BLOCKs
 *  to a database output stream. Also writes the next aggregation
 *  of BLOCKs: DATAFIELDS as handed over in <code>RawField</code> objects. 
 */
private class BlockWriter implements PwsBlockOutputStream, RawFieldWriter
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
   public BlockWriter ( OutputStream output, PwsCipher cipher, int format )
   {
      if ( output == null | cipher == null )
         throw new NullPointerException();
      
      out = output;
      this.cipher = cipher;
      blocksize = cipher.getBlockSize();
      fileVersion = format;
   }
   
   @Override
   public int getCount ()
   {
      return blockCount;
   }

   @Override
   public int getFormat ()
   {
      return fileVersion;
   }
   
   @Override
   public int getBlockSize ()
   {
      return blocksize;
   }

   @Override
   public boolean isClosed ()
   {
      return out == null;
   }
   
   @Override
   public void writeBlocks ( byte[] data, int offset, int length ) throws IOException
   {
      byte[] buf, buf2;

      if ( out == null )
         throw new IllegalStateException( "outputstream closed" );
      
      // prepare data (ensure correct block length)
      int blocks = length / blocksize;
      if ( length - blocks * blocksize > 0 ) {
    	 // "enrich" block space 
         blocks++;
         buf = Util.arraycopy( data, offset, blocks * blocksize );
         buf2 = cipher.encrypt( buf );
         hmac.update(buf);
         Util.destroyBytes(buf);
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
   public void writeBlocks ( byte[] data ) throws IOException
   {
      if ( out == null )
         throw new IllegalStateException( "outputstream closed" );
      
      writeBlocks( data, 0, data.length );
   }
   
   @Override
   public void writeRawField ( PwsRawField rawField ) throws IOException
   {
      rawField.writeEncrypted( out, cipher, fileVersion, hmac );
   }  

   @Override
   public void close () throws IOException
   {
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
