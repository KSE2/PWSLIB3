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
import java.nio.ByteBuffer;
import java.nio.charset.IllegalCharsetNameException;
import java.util.zip.CRC32;

import org.jpws.pwslib.crypto.CipherModeCBC;
import org.jpws.pwslib.crypto.PwsCipher;
import org.jpws.pwslib.crypto.ScatterCipher;
import org.jpws.pwslib.global.Global;
import org.jpws.pwslib.global.Log;
import org.jpws.pwslib.global.PwsChecksum;
import org.jpws.pwslib.global.Util;

/**
 *  A <code>RawField</code> contains the value of a  single <u>PWS data field</u> 
 *  (as it typically occurs in a PWS file). By default the value is stored in
 *  cleartext (decrypted) but my be caused to be stored encrypted instead.
 *  
 *  <p>Similar to the type <code>String</code>, <code>RawField</code> behaves
 *  largely as a constant and after creation of an instance its value cannot
 *  be altered, except by destruction.
 *  Data getter methods discriminate properly for blocked and unblocked data 
 *  and length.
 *  
 *  <p>RawField is used primarily in raw-field lists (e.g. the <code>HeaderFieldList</code>)
 *  by input and output handling classes, or as a uniform interface to storable 
 *  PWS fields.
 *
 *  @see org.jpws.pwslib.data.RawFieldList
 *  @see org.jpws.pwslib.data.HeaderFieldList
 */
public class PwsRawField implements Cloneable {

   private static final byte[] EMPTY_BLOCK = new byte[0];
   private static final PwsCipher VEIL_CIPHER = new ScatterCipher();
   private static final byte[] VEIL_IV = Util.getCryptoRand().nextBytes(VEIL_CIPHER.getBlockSize());
	
   int type;
   int length;
   private int crcValue;
   private boolean encrypted;
   private byte[] data = EMPTY_BLOCK;
   
   
   /**
    * Constructs a raw-field by reading its content from a PWS input block stream.
    * The stream is advanced for the number of blocks that define the next field.
    * 
    * @param bs <code>PwsBlockInputStream</code>
    * @param format int the file format version (interpretation schema)
    * @throws IOException
    */
   public PwsRawField (PwsBlockInputStream bs, int format) throws IOException {
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
   public PwsRawField (int type, byte[] data) {
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
   public PwsRawField (int type, int length, byte[] data) {
      init(type, length, data);
   }

   /**
    * Constructor for a raw-field. Parameter <code>length</code> defines the 
    * length value of the field independent from the size of the supplied 
    * <code>data</code> block. A copy of the <code>data</code> parameter is used.
    *    
    * @param type 0 .. 255; the field data type (convention of the PWS-File definition)
    * @param offs int start offset in data (0 if data is not supplied)
    * @param length the length of field data (in bytes)
    * @param data source of content of this field; any length (missing content will be
    *        supplemented by zero bytes); may be <b>null</b>    
    */
   public PwsRawField(int type, byte[] data, int start, int length) {
	  init(type, start, length, data);
   }

   private void init ( int type, int offs, int length, byte[] data ) {
      if ( length < 0 )
         throw new IllegalArgumentException( "illegal field length : " + length );
      if ( data != null && offs < 0 | offs > Math.max(0, data.length-1) )
          throw new IllegalArgumentException( "illegal data offset: " + offs );
      if ( (type & ~0xff) != 0 )
         throw new IllegalArgumentException( "illegal type value : " + type );
      
      // store values
      this.type = type;
      this.length = length;
	  if ( data != null && length > 0 ) {
		 this.data =  Util.arraycopy(data, offs, length);
	  } else if ( length > 0 ) {
	  	 this.data = new byte[length];
      }
   }
   
   private void init ( int type, int length, byte[] data ) {
	   if ( length < 0 )
	      throw new IllegalArgumentException( "illegal field length : " + length );
	   if ( (type & ~0xff) != 0 )
	      throw new IllegalArgumentException( "illegal type value : " + type );
	      
	   // store values
	   this.type = type;
	   this.length = length;
	   if ( data != null && length > 0 ) {
	      this.data =  Util.arraycopy(data, length);
	   } else if ( length > 0 ) {
		  this.data = new byte[length];
	   }
	}

   /** Tells this raw field whether to store its data block encrypted or in
    * cleartext. <p>Note: Method <code>getData()</code> always returns the 
    * cleartext.
    * 
    * @param encrypt boolean true == store ciphertext, false == store cleartext
    */
   public void setEncrypted (boolean encrypt) {
	   if ( encrypt ) {
		  // set encrypted branch
		  if ( encrypted ) return;
		  encrypted = true;
		  if ( hasData() ) {
			 getCrc(); // ensure we supply a CRC on the cleartext
			 PwsCipher cipher = createCipher();
			 int bs = cipher.getBlockSize();
			 int h = length % bs;
			 int len = length + bs - h;
			 if ( len > 1000 ) len += bs;  // redundant block ensures sufficient size to avoid array copy during writeEncrypted()
			 byte[] plain = h == 0 ? data : Util.arraycopy(data, len);
			 data = cipher.encrypt(plain);
			 Log.debug(8, "(PwsRawField.setEncrypted) data encrypted, type " + type + ", data = " + 
			       Util.bytesToHex(data, 0, Math.min(32, length)) + (length > 32 ? ".." : ""));
		  }

	   } else {
		  // set decrypted branch
		  if ( !encrypted ) return;
		  encrypted = false;
		  if ( hasData() ) {
			 PwsCipher cipher = createCipher();
			 data = cipher.decrypt(data);
			 Log.debug(8, "(PwsRawField.setEncrypted) data decrypted, type " + type + ", data = " + 
				       Util.bytesToHex(data, 0, Math.min(32, length)) + (length > 32 ? ".." : ""));
		  }
	   }
   }

   /** Creates the cipher to realise the encrypted data state.
    *  
    * @return PwsCipher
    */
   private PwsCipher createCipher () {
	   return new CipherModeCBC(VEIL_CIPHER, VEIL_IV);
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
   public static PwsRawField makeTextField (int type, String text) {
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
   public static PwsRawField makeTimeField (int type, long time, int length) {
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
   public Object clone () {
      try { 
    	 PwsRawField field = (PwsRawField)super.clone(); 
    	 if ( field.data != EMPTY_BLOCK ) {
            field.data = (byte[])this.data.clone();
    	 }
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
   public boolean equals ( Object obj ) {
      if ( obj == null || !(obj instanceof PwsRawField)) return false;
      
      PwsRawField fld = (PwsRawField)obj;
      return fld.type == type &&
             (fld.data == data || fld.getCrc() == getCrc());
   }

   /** Hashcode complying with proprietary equals function.  
    */
   @Override
   public int hashCode () {
      int i = getCrc();
      i ^= type << (length % 16);
      return i;
   }

   /** Returns the field's data type as defined in the header block value.
    */
   public int getType () {
      return type;
   }

   /** Returns the length of the field value as defined in the header block value.
    */
   public int getLength () {
      return length;
   }

   /** Returns the CRC32 value over the valid data of this raw field.
    * If there is no data defined or the length is zero, zero is returned.
    * 
    * @return int CRC32 value
    */
   public int getCrc () {
	   if ( crcValue == 0 && hasData() ) {
		   CRC32 crc = new CRC32();
		   crc.update(data, 0, length);
		   crcValue = (int)crc.getValue();
	   }
	   return crcValue;
   }

   /** Returns the decrypted version of this field's data value. This may be
    * the "data" variable itself if no encryption is in place, or a new byte
    * buffer if the field is encrypted.
    * 
    * @return byte[] cleartext field data 
    */
   private byte[] getDecryptedData () {
      byte[] buf = data;
      if ( encrypted && hasData() ) {
		 PwsCipher cipher = createCipher();
		 buf = cipher.decrypt(data);
	  }
      return buf;
   }
   
   /** Returns a data array (a copy) of this field's value of 
    *  the length as defined in the field's length value. This always returns
    *  the cleartext value, even if the field was set to store encrypted.
    *  
    * @return array of bytes
    */
   public byte[] getData () {
      if ( length == 0 ) {
         return EMPTY_BLOCK;
      }
      return Util.arraycopy( getDecryptedData(), length );
   }
   
   /** Renders a direct reference to the data storage block of this field.
    * This is for internal purposes of the PWSLIB package only!
    *   
    * @return byte[]
    */
   byte[] getDataDirect () {
	   return data;
   }
   
   /** Returns the value of this field as a <code>PwsPassphrase</code>
    *  decoded to the parameter character set.
    * 
    *  @return <code>PwsPassphrase</code>
    */
   public PwsPassphrase getPassphrase ( String charset ) {
      byte[] databuf = getDecryptedData();
      PwsPassphrase pass = new PwsPassphrase(databuf, 0, length, charset);
      if ( databuf != data ) {
         Util.destroyBytes(databuf);
      }
      return pass;
   }
   
   /** Returns a total size of this field when stored on a PWS persistent state.
    * 
    *  @param format int applicable file format version
    *  @return int blocked data length of the field 
    */
   public int getBlockedSize ( int format ) {
      return pwsFieldBlockSize(length, format);
   }

   /** Returns a data array of this field's value of the length as
    *  defined by data-blocking requirements (<code>blocksize</code>).
    *  The result block may be a section of the stored block,
    *  starting at a specified offset. 
    *  <p>The result may be larger or smaller than the field's length value.
    *  
    *  @param data byte[] the field's cleartext data block
    *  @param blocksize int cipher blocksize
    *  @param offset int starting offset of resulting data block 
    *  @param format int applicable file format version
    * 
    *  @return array of bytes or <b>null</b> if no data blocks are required
    *          to store the value of the field (includes empty data) 
    */
   private ByteBuffer getBlockedDataIntern (byte[] data, int blocksize, int offset, int format) {
      int dblocks, blockedLen, segLen;
      byte[] rand;
      
      if ( data == null ) return null;
      
      // calculate size of data block needed to store this field's user data from offset
      // we assume here that offset is within the range of a single block
      dblocks = pwsFieldBlockCount(length, format) - 1;
      blockedLen = dblocks * blocksize;
      if ( blockedLen == 0 ) return null;
      
      // ensure we return a data block large enough 
      int targetSize = offset+blockedLen;
      if ( data.length < targetSize ) {
    	  data = Util.arraycopy(data, targetSize);
    	  Log.log(10, "(PwsRawField.getBlockedDataIntern) data array-copy, length=" + targetSize);
      } else {
    	  Log.log(10, "(PwsRawField.getBlockedDataIntern) avoided data copy, length=" + targetSize);
      }

      // create ByteBuffer and fill segment over size with random data
      ByteBuffer buf = ByteBuffer.wrap( data, offset, blockedLen );
      buf.mark(); 
      segLen = length - offset;  // length of user data segment 
      rand = Util.getCryptoRand().nextBytes( blockedLen - segLen );
      buf.position(buf.position() + segLen);
      buf.put(rand);
      buf.reset();
//      System.arraycopy( rand, 0, buf, segLen, rand.length );
      return buf;
   }

   /** Returns the data of this field as a <code>String</code> value.
    * 
    * @param charset String charset name to be applied to the stored byte array;
    *        <b>null</b> for system default
    * @return String text string (may be empty but not <b>null</b>)
    * @throws IllegalStateException if charset cannot be applied
    */
   public String getString ( String charset ) {
      if ( length == 0 ) return "";
      if ( charset == null ) {
         charset = Global.getDefaultCharset();
      }
      
      try { 
    	  String hstr = new String(getDecryptedData(), 0, length, charset); 
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
   public int getBlockCount ( int format ) {
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
   public static int pwsFieldBlockCount ( int datalength, int format ) {
      int offset, cLength, blockCount, blocksize;
      
      if ( format == Global.FILEVERSION_3 ) {
         blocksize = 16;
         offset =  11;
      } else {
         blocksize = 8;
         offset =  0;
      }
      
      blockCount = 1; // basic block of a field
      cLength = Math.max( 0, datalength-offset );  // length of data outside of basic block
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
   public static int pwsFieldBlockSize ( int datalength, int format ) {
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
      byte[] data1, buffer, block;
      long v;
      int blocksize, sliceLen, segLen;
      
      if ( out == null | cipher == null )
         throw new NullPointerException();
      
      blocksize = cipher.getBlockSize();
      segLen = blocksize - 5;
      data1 = getDecryptedData(); 
      
      // compile length and type field of header-block
      block = new byte[ blocksize ];
      v = ((long)length & 0xffffffffL) | (((long)type & 0xffL) << 32);
      Util.writeLongLittle(v, block, 0);

      // if V3 format, add a slice of field data 
      if ( hasData() && format == Global.FILEVERSION_3 ) {
         sliceLen = Math.min(segLen, length);
         System.arraycopy(data1, 0, block, 5, sliceLen);
      } else {
         sliceLen = 0;
      }
      
      // write the field header-block
      buffer = cipher.encrypt(block);
      Util.destroyBytes(block);
      out.write(buffer);

      // write data blocks
      ByteBuffer bbuf = getBlockedDataIntern(data1, blocksize, sliceLen, format);
      if ( bbuf != null ) {
         byte[] buf2 = cipher.encrypt(bbuf.array(), bbuf.position(), bbuf.remaining());
         out.write(buf2);
         Util.destroyBytes(buffer);
      }
      
      // update checksum
      if ( checksum != null ) {
         checksum.update(data1, 0, length);
      }

      // eliminate cleartext data if field is encrypted
      if ( encrypted ) {
          Util.destroyBytes(data1);
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
      
      // read field header (throw EOF if void)
      if ( (block = blockStream.readBlock()) == null )
         throw new EOFException();
      
      // determine field header block values and number of data blocks to be read
      header = new FieldHeader(block, format);
      Util.destroyBytes(block);

      // create field elements
      length = header.length;
      type = header.type;
      if ( header.length > 0 ) {
         // read data blocks from stream and add to data buffer
         data = new byte[ header.length ];
         int offset = 0;

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
      }
      
      header.clear();
   }  // readStream
   
   /** Whether this raw field contains data. A length value of zero is 
    * equivalent to void data (returns false).
    * 
    * @return boolean true == contains data of length &gt; 0
    */
   public boolean hasData () {
	   return length > 0;
   }
   
   /** Whether this raw field stores data encrypted internally.
    * 
    * @return boolean true == stores encrypted
    */
   public boolean isEncrypted () {
	   return encrypted;
   }
   
   /** Erases the contents of the data array and sets all values to zero.
    *  After this, the field has no further meaning, sensitive data been 
    *  effectively cleaned out.
    */
   public void destroy () {
      type = 0;
      length = 0;
      crcValue = 0;
      Util.destroyBytes( data );
      data = EMPTY_BLOCK;
   }

	@Override
	public String toString() {
		return "PwsRawField " + type + ", length=" + length + ", crc=" + getCrc();
	}
}