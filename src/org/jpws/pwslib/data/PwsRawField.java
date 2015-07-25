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
 *  <p>As for its cleartext status, <code>RawField</code> is inapproriate for storing
 *  sensitive data like e.g. a password.
 *  <p>RawField is used primarily in rawfield lists (e.g. the <code>HeaderFieldList</code>)
 *  by input and output handling classes, or as a uniform interface to storable 
 *  PWS fields.
 *
 *  @see org.jpws.pwslib.data.RawFieldList
 *  @see org.jpws.pwslib.data.HeaderFieldList
 *   
 *  @since 2-0-0
 */
public class PwsRawField implements Cloneable
{
   int type;
   int length;
   byte[] data;
   
   
   /**
    * Constructs a rawfield by reading its content from a PWS input blockstream.
    * The stream is advanced for the number of blocks that define the next field.
    * 
    * @param bs <code>PwsBlockInputStream</code>
    * @param format the file format version (interpretation schema)
    * @throws IOException
    */
   public PwsRawField ( PwsBlockInputStream bs, int format ) throws IOException
   {
      data  = new byte[ 0 ];
      readStream( bs, format );
   }
   
   /**
    * Constructor for a rawfield with a length value and content identical to
    * the parameter byte array. The byte array may be of any size.
    *      
    * @param type 0 .. 255; the field data type (convention of the PWS-File definition)
    * @param data content of the field (any length); may be <b>null</b> in which
    *        case length 0 is assumed    
    */
   public PwsRawField ( int type, byte[] data )
   {
      int len;
      
      len = data == null ? 0 : data.length;
      init( type, len, data );
   }  // constructor
   
   /**
    * Creates a rawfield from a text string. The encoding used
    * is UTF-8; if encoding fails, a runtime exception is thrown.
    *      
    * @param type 0 .. 255; the field data type (convention of the PWS-File definition)
    * @param text content of the field as a text string (any length); 
    *        may be <b>null</b> in which case length 0 is assumed    
    * @throws IllegalCharsetNameException if UTF-8 is not supported by JRE    
    * @since 2-1-0 
    */
   public static PwsRawField makeTextField ( int type, String text )
   {
      String chs;
      byte[] buf;
      
      buf = null;
      chs = "utf-8";
      if ( text != null )
         try { buf = text.getBytes( chs ); }
         catch ( UnsupportedEncodingException e )
         { throw new IllegalCharsetNameException( chs ); }
         
      return new PwsRawField( type, buf );
   }
   
   /**
    * Creates a rawfield for a standard time value. Time is
    * passed in universal epoch milliseconds, but the field value stored is
    * is in <b>seconds</b> (= div 1000). (Time is represented in Little-Endian 
    * manner as an integer value ideally of 8 or 4 bytes length.)
    *      
    * @param type 0 .. 255; the field data type (convention of the PWS-File definition)
    * @param time long time value in epoch milliseconds    
    * @param length length in bytes of binary integer representation (minimum 4)
    * @since 2-1-0 
    */
   public static PwsRawField makeTimeField ( int type, long time, int length )
   {
      byte[] buf;
      
      if ( length < 4 )
         throw new IllegalArgumentException( "illegal length parameter".concat( String.valueOf(length ) ));
      
      time = time / 1000;
      buf = new byte[length];
      if ( length < 8 )
         Util.writeIntLittle( (int)time, buf, 0 );
      else
         Util.writeLongLittle( time, buf, 0 );
      
      return new PwsRawField( type, buf );
   }
   
   /**
    * Constructor for a RawField. <code>length</code> defines the length of the 
    * field value independently from the size of the supplied <code>data</code> block.
    *    
    * @param type 0 .. 255; the field data type (convention of the PWS-File definition)
    * @param length the length of field data (in bytes)
    * @param data source of content of this field; any length (missing content will be
    *        supplemented by zero bytes); may be <b>null</b>    
    */
   public PwsRawField ( int type, int length, byte[] data )
   {
      init( type, length, data );
   }  // constructor

   private void init ( int type, int length, byte[] data )
   {
      if ( length < 0 )
         throw new IllegalArgumentException( "illegal field length : " + length );
      if ( (type & ~0xff) != 0 )
         throw new IllegalArgumentException( "illegal type value : " + type );
      
      // store values
      this.type = type;
      this.length = length;
      this.data = data != null ? Util.arraycopy( data, length ) : new byte[0];
   }  // init
   
   /** Returns a deep clone of this rawfield. */
   public Object clone ()
   {
      PwsRawField o;
      
      try { 
         o = (PwsRawField)super.clone(); 
         o.data = (byte[])this.data.clone();
         return o;
      }
      catch ( CloneNotSupportedException e )
      {
         return null;
      }
   }
   
   /** Two raw fields are equal if and only if their type and data values
    * are equal.
    * 
    * @return <b>true</b> if and only if obj.type == this.type & 
    *         equalData( obj.data, this.data )   
    * @since 2-1-0 
    */ 
   public boolean equals ( Object obj )
   {
      PwsRawField fld;
      
      if ( obj == null )
         return false;
      
      fld = (PwsRawField)obj;
      return fld.type == type &&
             ( fld.data == data || 
             ( fld.data != null && data != null && Util.equalArrays( fld.data, data ) ));
   }

   /** Hashcode complying with proprietary equals function.  
    *  @since 2-1-0 
    */
   public int hashCode ()
   {
      int i = 0;

      if ( data != null )
         i = Util.arrayHashcode( data );
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
      if ( data == null )
         return new byte[ length ];
      
      return Util.arraycopy( data, length );
   }
   
   /** Returns the value of this field as a <code>PwsPassphrase</code>
    *  decoded to the parameter character set.
    * 
    *  @return <code>PwsPassphrase</code>
    */
   public PwsPassphrase getPassphrase ( String charset )
   {
      PwsPassphrase pass;
      byte[] databuf;

      databuf = getData();
      pass = new PwsPassphrase( databuf, charset );
      Util.destroyBytes( databuf );
      return pass;
   }
   
   /** Returns a total size of this field when stored on a PWS persistent state.
    * 
    *  @param format applicable file format version
    *  @return int blocked data length of the field 
    *  @since 2-0-0
    */
   public int getBlockedSize ( int format )
   {
      return pwsFieldBlockSize( length, format );
   }

   /** Returns a data array of this field's value of the length as
    *  defined by data-blocking requirements (blocksize).
    *  The result block may be a section of the stored block,
    *  starting at a specified offset. 
    *  The result may be larger or smaller than the field's length value.
    *  
    *  @param blocksize cipher blocksize
    *  @param offset starting offset of resulting data block 
    *  @param format applicable file format version
    * 
    *  @return array of bytes or <b>null</b> if no data blocks are required
    *          to store the value of the field (includes empty data) 
    */
   private byte[] getBlockedDataIntern ( int blocksize, int offset, int format )
   {
      int dblocks, blockedLen, segLen;
      byte[] buf, rand;
      
      dblocks = pwsFieldBlockCount( length, format ) - 1;
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
    * @param charset charset to be applied on the stored byte stream
    *        (<b>null</b> for system default)
    * @return decrypted text string (may be empty but not <b>null</b>)
    */
   public String getString ( String charset )
   {
      String hstr;

      if ( data == null | length == 0 )
         return "";
      
      if ( charset == null )
         charset = Global.getDefaultCharset();
      
      try { hstr = new String( data, 0, length, charset ); }
      catch ( UnsupportedEncodingException e )
      {
         hstr = "** enc error **";
      }
      return hstr;
   }  // getString
   
   /** The total number of data blocks required to store this field on a 
    * pesistent state (PWS file).
    * 
    * @param format applicable file format version
    * @return int number of required data blocks 
    * @since 2-0-0
    */
   public int getBlockCount ( int format )
   {
      return pwsFieldBlockCount( length, format );
   }

   /**
    * Returns the number of data blocks required to store a PWS data field
    * according to the formatting rules of a persistent state (PWS file).
    * 
    * @param datalength length in bytes of usable data of the field
    * @param format format version number of the persistent state
    * @return total number of data blocks required to store the field
    * @since 2-0-0
    */
   public static int pwsFieldBlockCount ( int datalength, int format )
   {
      int offset, cLength, blockCount, blocksize;
      
      if ( format == Global.FILEVERSION_3 )
      {
         blocksize = 16;
         offset =  11;
      }
      else
      {
         blocksize = 8;
         offset =  0;
      }
      
      blockCount = 1; // basic block of a field
      cLength = Math.max( 0, datalength - offset );  // length of data outside of basic block
      blockCount += cLength / blocksize;  // required data blocks
      if ( cLength % blocksize > 0 ||
           (format < Global.FILEVERSION_3 & cLength == 0))
         blockCount++;  // correction
      
      return blockCount;
   }

   /**
    * Returns the total data size in bytes required to store a PWS data field
    * according to the formatting rules of a persistent state (PWS file).
    * 
    * @param datalength length in bytes of usable data of the field
    * @param format format version number of the persistent state
    * @return number of bytes required to store the field
    * @since 2-0-0
    */
   public static int pwsFieldBlockSize ( int datalength, int format )
   {
      int blocksize;
      
      blocksize = format == Global.FILEVERSION_3 ? 16 : 8; 
      return blocksize * pwsFieldBlockCount( datalength, format );
   }
   
   /** Writes the contents of this rawfield to an output stream, encrypted by
    * the parameter cipher, blocked and formatted according to the PWS rules for
    * the specified format version.
    * 
    * @param out target data output stream
    * @param cipher PwsCipher (writing direction) 
    * @param format the PWS file version format (for values see class <code>Global</code>)
    * @throws IOException
    */
   public void writeEncrypted ( OutputStream out, PwsCipher cipher, int format ) throws IOException
   {
      writeEncrypted( out, cipher, format, null );
   }
   
   /** Writes the contents of this rawfield to an output stream, encrypted by
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
   public void writeEncrypted ( OutputStream out, PwsCipher cipher, int format, 
         PwsChecksum checksum ) throws IOException
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
      Util.writeLongLittle( v, block, 0 );

      // if V3 format, add a slice of field data 
      if ( format == Global.FILEVERSION_3 )
      {
         sliceLen = Math.min( segLen, length );
         System.arraycopy( data, 0, block, 5, sliceLen );
      }
      else
      {
         sliceLen = 0;
      }
      
      // write the field header-block
      buffer = cipher.encrypt( block );
      Util.destroyBytes( block );
      out.write( buffer );

      // write data blocks
      buffer = getBlockedDataIntern( blocksize, sliceLen, format );
      if ( buffer != null )
      {
         buffer2 = cipher.encrypt( buffer );
         out.write( buffer2 );
         Util.destroyBytes( buffer );
      }
      
      // update checksum
      if ( checksum != null )
         checksum.update( data );
   }  // writeEncrypted
   
   /** Reads and determines the contents of this rawfield from an input
    *  blockstream, depending on the specified file format.
    * 
    * @param bs block input stream
    * @param format the applicable PWS file version format (values from <code>Global</code>)
    * @throws EOFException if there are insufficient blocks left in the stream
    *         to fully read the next rawfield
    * @throws IOException
    */
   private void readStream ( PwsBlockInputStream blockStream, int format ) throws IOException
   {
      FieldHeader header;
      byte[] block;
      int offset;
      
      // read field header (throw EOF if void)
      if ( (block = blockStream.readBlock()) == null )
         throw new EOFException();
      
      // determine field header block values and number of data blocks to be read
      header = new FieldHeader( block, format );
      Util.destroyBytes(block);

      // create field elements incl. data buffer
      length = header.length;
      type = header.type;
      data = new byte[ header.length ];
      offset = 0;
      
      // collect header block data segment (V3 files)
      if ( header.data != null )
      {
         offset = header.data.length;
         System.arraycopy( header.data, 0, data, 0, offset );
      }

      // collect following (V3: additional) data blocks
      block = blockStream.readBlocks( header.blocks );
      if ( block == null )
         throw new EOFException();
      System.arraycopy( block, 0, data, offset, header.length - offset );
      Util.destroyBytes( block );

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