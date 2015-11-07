/*
 *  File: PwsRawField.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 07.08.2005
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
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.IllegalCharsetNameException;

import org.jpws.pwslib.crypto.PwsCipher;
import org.jpws.pwslib.global.Global;
import org.jpws.pwslib.global.PwsChecksum;
import org.jpws.pwslib.global.Util;

/**
 *  A <code>RawField</code> contains a cleartext (decrypted) value of a
 *  single <u>PWS data field</u> (as it typically occurs in a PWS file). 
 *  Similar to the type <code>String</code>, <code>RawField</code> behaves
 *  largely as a constant and after creation of an instance its value cannot
 *  be altered, except by destruction.
 *  Data getter methods discriminate properly for blocked and unblocked data 
 *  and length.
 *  
 *  <p>As for its cleartext status, <code>RawField</code> is inappropriate for 
 *  storing sensitive data like e.g. a password.
 *  <p>RawField is used primarily in raw-field lists (e.g. the <code>HeaderFieldList</code>)
 *  by input and output handling classes, or as a uniform interface to storable 
 *  PWS fields.
 *
 *  @see org.jpws.pwslib.data.RawFieldList
 *  @see org.jpws.pwslib.data.HeaderFieldList
 */
public class PwsRawField implements Cloneable
{
   int type;
   int length;
   byte[] data;
   
   
   /**
    * Constructs a raw-field by reading its content from a PWS input block stream.
    * The stream is advanced for the number of blocks that define the next field.
    * 
    * @param bs <code>PwsBlockInputStream</code>
    * @param format int the file format version (interpretation schema)
    * @throws IOException
    */
   public PwsRawField (PwsBlockInputStream bs, int format) throws IOException
   {
      data  = new byte[0];
      readStream(bs, format);
   }
   
   /**
    * Constructor for a raw-field with a length value and content identical to
    * the parameter byte array. The byte array may be of any size. A copy of
    * the <code>data</code> parameter is used.
    *      
    * @param type int 0..255; the field's data type 
    *                 (convention of the PWS format definition)
    * @param data byte array, content of the field (any length); may be 
    *             <b>null</b> in which case length 0 is assumed    
    */
   public PwsRawField (int type, byte[] data)
   {
      int len = data == null ? 0 : data.length;
      init(type, len, data);
   }
   
   /**
    * Constructor for a raw-field. Parameter <code>length</code> defines the 
    * length value of the field independent from the size of the supplied 
    * <code>data</code> block. A copy of the <code>data</code> parameter is used.
    *    
    * @param type 0 .. 255; the field data type (convention of the PWS-File definition)
    * @param length the length of field data (in bytes)
    * @param data source of content of this field; any length (missing content will be
    *        supplemented by zero bytes); may be <b>null</b>    
    */
   public PwsRawField (int type, int length, byte[] data)
   {
      init(type, length, data);
   }

   private void init ( int type, int length, byte[] data )
   {
      if ( length < 0 )
         throw new IllegalArgumentException( "illegal field length : " + length );
      if ( (type & ~0xff) != 0 )
         throw new IllegalArgumentException( "illegal type value : " + type );
      
      // store values
      this.type = type;
      this.length = length;
      this.data = data != null ? Util.arraycopy(data, length) : new byte[0];
   }
   
   /**
    * Creates a raw-field from a text string. The encoding used
    * is UTF-8; if encoding fails, a runtime exception is thrown.
    *      
    * @param type int 0..255; the field's data type 
    *             (convention of the PWS format definition)
    * @param text String content of the field as a text string (any length); 
    *        may be <b>null</b> in which case length 0 is assumed    
    * @throws IllegalCharsetNameException if UTF-8 is not supported by JRE   
    * @throws IllegalArgumentException if field type is illegal  
    */
   public static PwsRawField makeTextField (int type, String text)
   {
      byte[] buf = null;
      if ( text != null ) {
         try { 
        	 buf = text.getBytes( "utf-8" ); 
         } catch ( UnsupportedEncodingException e ) {
        	 throw new IllegalCharsetNameException( "utf-8" ); 
       	 }
      }
      return new PwsRawField(type, buf);
   }
   
   /**
    * Creates a raw-field for a standard time value. Time is
    * passed in universal epoch milliseconds, but the field value stored is
    * is in <b>seconds</b> (= div 1000). (Time is represented in Little-Endian 
    * manner as an integer value ideally of 8 or 4 bytes length.)
    *      
    * @param type int 0..255; the field's data type 
    *             (convention of the PWS format definition)
    * @param time long time value in epoch milliseconds    
    * @param length int length in bytes of binary integer representation 
    *               (minimum 4)
    * @throws IllegalArgumentException if length or field type is illegal              
    */
   public static PwsRawField makeTimeField (int type, long time, int length)
   {
      if ( length < 4 | length > 8 )
         throw new IllegalArgumentException( "illegal length parameter"
        		 .concat( String.valueOf(length ) ));
      
      time = time / 1000;
      byte[] buf = new byte[length];
      if ( length < 8 ) {
         Util.writeIntLittle( (int)time, buf, 0 );
      } else {
         Util.writeLongLittle( time, buf, 0 );
      }
      return new PwsRawField(type, buf);
   }
   
   /** Returns a deep clone of this raw-field. */
   @Override
   public Object clone ()
   {
      try { 
    	 PwsRawField field = (PwsRawField)super.clone(); 
         field.data = (byte[])this.data.clone();
         return field;

      } catch ( CloneNotSupportedException e ) {
         return null;
      }
   }
   
   /** Two raw fields are equal if and only if their type and data values
    * are equal.
    * 
    * @return <b>true</b> if and only if obj.type == this.type & the data
    *         arrays are identical or have equal contents 
    */ 
   @Override
   public boolean equals ( Object obj )
   {
      if ( obj == null || !(obj instanceof PwsRawField))
         return false;
      
      PwsRawField fld = (PwsRawField)obj;
      return fld.type == type &&
             (fld.data == data || 
             (fld.data != null && data != null && Util.equalArrays( fld.data, data )));
   }

   /** Hashcode complying with proprietary equals function.  
    */
   @Override
   public int hashCode ()
   {
      int i = data == null ? 0 : Util.arrayHashcode( data );
      i ^= type << (length % 8);
      return i;
   }

   /** Returns the field's data type as defined in the header block value.
    */
   public int getType ()
   {
      return type;
   }

   /** Returns the length of the field value as defined in the header block value.
    */
   public int getLength ()
   {
      return length;
   }

   /** Returns a data array (copy) of this field's value of 
    *  the length as defined in the field's length value.
    *  
    * @return array of bytes
    */
   public byte[] getData ()
   {
      if ( data == null ) {
         return new byte[ length ];
      }
      return Util.arraycopy(data, length);
   }
   
   /** Returns the value of this field as a <code>PwsPassphrase</code>
    *  decoded to the parameter character set.
    * 
    *  @return <code>PwsPassphrase</code>
    */
   public PwsPassphrase getPassphrase ( String charset )
   {
      byte[] databuf = getData();
      PwsPassphrase pass = new PwsPassphrase(databuf, charset);
      Util.destroyBytes(databuf);
      return pass;
   }
   
   /** Returns a total size of this field when stored on a PWS persistent state.
    * 
    *  @param format int applicable file format version
    *  @return int blocked data length of the field 
    */
   public int getBlockedSize ( int format )
   {
      return pwsFieldBlockSize(length, format);
   }

   /** Returns a data array of this field's value of the length as
    *  defined by data-blocking requirements (<code>blocksize</code>).
    *  The result block may be a section of the stored block,
    *  starting at a specified offset. 
    *  <p>The result may be larger or smaller than the field's length value.
    *  
    *  @param blocksize int cipher blocksize
    *  @param offset int starting offset of resulting data block 
    *  @param format int applicable file format version
    * 
    *  @return array of bytes or <b>null</b> if no data blocks are required
    *          to store the value of the field (includes empty data) 
    */
   private byte[] getBlockedDataIntern (int blocksize, int offset, int format)
   {
      int dblocks, blockedLen, segLen;
      byte[] buf, rand;
      
      dblocks = pwsFieldBlockCount(length, format) - 1;
      blockedLen = dblocks * blocksize;
      
      if ( data == null | blockedLen == 0 )
         return null;
      
      // copy additional data block segment and fill overfoot with random data 
      buf = Util.arraycopy( data, offset, blockedLen );
      segLen = data.length - offset;  // length of user data segment 
      rand = Util.getCryptoRand().nextBytes( blockedLen - segLen );
      System.arraycopy( rand, 0, buf, segLen, rand.length );
      return buf;
   }

   /** Returns the data of this field as a <code>String</code> value.
    * 
    * @param charset String charset name to be applied to the stored byte array;
    *        <b>null</b> for system default
    * @return String text string (may be empty but not <b>null</b>)
    * @throws IllegalStateException if charset cannot be applied
    */
   public String getString ( String charset )
   {
      if ( data == null || length == 0 ) {
         return "";
      }

      if ( charset == null ) {
         charset = Global.getDefaultCharset();
      }
      
      try { 
    	  String hstr = new String(data, 0, length, charset); 
          return hstr;
      } catch ( UnsupportedEncodingException e ) {
         throw new IllegalStateException("** decoding not supported **: ".concat(charset));
      }
   }  // getString
   
   /** The total number of data blocks required to store this field on a 
    * persistent state (PWS file).
    * 
    * @param format applicable file format version
    * @return int number of required data blocks 
    */
   public int getBlockCount ( int format )
   {
      return pwsFieldBlockCount(length, format);
   }

   /**
    * Returns the number of data blocks required to store a PWS data field
    * according to the formatting rules of a persistent state (PWS file).
    * 
    * @param datalength int length in bytes of usable data of the field
    * @param format int format version number of the persistent state
    * @return total number of data blocks required to store the field
    */
   public static int pwsFieldBlockCount ( int datalength, int format )
   {
      int offset, cLength, blockCount, blocksize;
      
      if ( format == Global.FILEVERSION_3 ) {
         blocksize = 16;
         offset =  11;
      } else {
         blocksize = 8;
         offset =  0;
      }
      
      blockCount = 1; // basic block of a field
      cLength = Math.max( 0, datalength - offset );  // length of data outside of basic block
      blockCount += cLength / blocksize;  // required data blocks
      if ( cLength % blocksize > 0 ||
           (format < Global.FILEVERSION_3 & cLength == 0)) {
         blockCount++;  // correction
      }
      
      return blockCount;
   }

   /**
    * Returns the total data size in bytes required to store a PWS data field
    * according to the formatting rules of a persistent state (PWS file).
    * 
    * @param datalength int length in bytes of usable data of the field
    * @param format int format version number of the persistent state
    * @return number of bytes required to store the field
    */
   public static int pwsFieldBlockSize ( int datalength, int format )
   {
      int blocksize = format == Global.FILEVERSION_3 ? 16 : 8; 
      return blocksize * pwsFieldBlockCount(datalength, format);
   }
   
   /** Writes the contents of this raw-field to an output stream, encrypted by
    * the parameter cipher, blocked and formatted according to the PWS rules for
    * the specified format version.
    * 
    * @param out OutputStream target data output stream
    * @param cipher PwsCipher (writing direction) 
    * @param format int the PWS file version format 
    *        (for values see class <code>Global</code>)
    * @throws IOException
    */
   public void writeEncrypted (OutputStream out, PwsCipher cipher, int format)
		   throws IOException
   {
      writeEncrypted(out, cipher, format, null);
   }
   
   /** Writes the contents of this raw-field to an output stream, encrypted by
    * the parameter cipher, blocked and formatted according to the PWS rules for
    * the specified format version and optionally updating a checksum object.
    * 
    * @param out target data output stream
    * @param cipher PwsCipher (writing direction) 
    * @param format the PWS file version format (for values see class <code>Global</code>)
    * @param checksum a <code>PwsChecksum</code> which gets updated by the
    *        data content of this field; may be <b>null</b>
    * @throws IOException
    */
   public void writeEncrypted (OutputStream out, PwsCipher cipher, int format, 
         PwsChecksum checksum) throws IOException
   {
      byte[] buffer, buffer2, block;
      long v;
      int blocksize, sliceLen, segLen;
      
      if ( out == null | cipher == null )
         throw new NullPointerException();
      
      blocksize = cipher.getBlockSize();
      segLen = blocksize - 5;
      
      // compile length and type field of header-block
      block = new byte[ blocksize ];
      v = ((long)length & 0xffffffffL) | (((long)type & 0xffL) << 32);
      Util.writeLongLittle(v, block, 0);

      // if V3 format, add a slice of field data 
      if ( format == Global.FILEVERSION_3 ) {
         sliceLen = Math.min(segLen, length);
         System.arraycopy(data, 0, block, 5, sliceLen);
      } else {
         sliceLen = 0;
      }
      
      // write the field header-block
      buffer = cipher.encrypt(block);
      Util.destroyBytes(block);
      out.write(buffer);

      // write data blocks
      buffer = getBlockedDataIntern(blocksize, sliceLen, format);
      if ( buffer != null ) {
         buffer2 = cipher.encrypt(buffer);
         out.write(buffer2);
         Util.destroyBytes(buffer);
      }
      
      // update checksum
      if ( checksum != null ) {
         checksum.update(data);
      }
   }  // writeEncrypted
   
   /** Reads and determines the contents of this raw-field from an input
    *  blockstream, depending on the specified file format.
    * 
    * @param blockStream PwsBlockInputStream block input stream
    * @param format int the applicable PWS file version format 
    *               (values from <code>Global</code>)
    * @throws EOFException if there are insufficient blocks left in the stream
    *         to fully read the next raw-field
    * @throws IOException
    */
   private void readStream ( PwsBlockInputStream blockStream, int format ) 
		   throws IOException
   {
      FieldHeader header;
      byte[] block;
      int offset;
      
      // read field header (throw EOF if void)
      if ( (block = blockStream.readBlock()) == null )
         throw new EOFException();
      
      // determine field header block values and number of data blocks to be read
      header = new FieldHeader(block, format);
      Util.destroyBytes(block);

      // create field elements incl. data buffer
      length = header.length;
      type = header.type;
      data = new byte[ header.length ];
      offset = 0;
      
      // collect header block data segment (V3 files)
      if ( header.data != null ) {
         offset = header.data.length;
         System.arraycopy(header.data, 0, data, 0, offset);
      }

      // collect following (V3: additional) data blocks
      block = blockStream.readBlocks( header.blocks );
      if ( block == null ) {
         throw new EOFException();
      }
      System.arraycopy(block, 0, data, offset, header.length - offset);
      Util.destroyBytes(block);

      header.clear();
   }  // readStream
   
   /** Erases the contents of the data array and sets all values to zero.
    *  After this, the field has no further meaning, sensitive data been 
    *  effectively cleaned out.
    */
   public void destroy ()
   {
      type = 0;
      length = 0;
      Util.destroyBytes( data );
      data = null;
   }
}