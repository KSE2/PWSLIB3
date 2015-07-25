package org.jpws.pwslib.data;

import java.io.IOException;
import java.io.InputStream;
import java.util.NoSuchElementException;

import org.jpws.pwslib.crypto.PwsCipher;
import org.jpws.pwslib.global.PwsChecksum;

/**
 * Class forming an iterator over {@link PwsRawField} objects
 * decrypted from an underlying blocked input stream (decrypted) 
 * which comes from a persistent state of a PWS file. 
 * 
 * <p>This implements the <code>Iterator</code> interface extended by a
 * close operation and a blocksize. This reader analyses
 * a block stream from the underlying data input source 
 * and renders elements of type <code>PwsRawField</code> in the 
 * order as they are encountered in the source.  
 * 
 * <p>Closing the reader is possible to inform the object that
 * no more input is needed. The reader will then behave
 * as if the end of the stream were reached. (Closing is
 * automatically performed when the last data element of
 * the file was read from the reader.) The close operation
 * does, however, not close the underlying input streams.
 * 
 * <p>The {@link PwsChecksum} that is optionally supplied to the constructors
 * serves building up the verification checksum of a V3 persistent state.
 * It can only be used for meaningful results <b>after</b> reading of
 * all fields has been completed (<code>hasNext() == false</code>). 
 * The initial state of the checksum is regularly the result of reading
 * the V3 file header.
 * 
 * @see PwsFileInputSocket
 * @see PwsFileHeaderV3
 * @since 2-0-0
 */
class RawFieldReader implements PwsRawFieldReader
{

   private PwsBlockInputStream blockStream;
   private PwsRawField nextField;
   private PwsChecksum hmac;
   private int blocksize;
   private int fileVersion;

   /**
    * Creates a rawfield reader from the input source PWS block stream and 
    * a file format version as interpretation scheme. 
    *   
    * @param bs <code>PwsBlockInputStream</code> input stream supplying decrypted data blocks
    *        from a PWS file 
    * @param format the file format version
    * @param hmac <code>PwsChecksum</code> that is updated with resulting field values 
    *        as reading progresses (this serves building up the verification checksum of the PWS file);
    *        may be <b>null</b> 
    * @throws IOException
    */
   public RawFieldReader ( PwsBlockInputStream bs, int format, PwsChecksum hmac  ) throws IOException
   {
      init( bs, format, hmac );
   }
   
   
   /**
    * Creates a rawfield reader from the plain source data stream, a cryptographical cipher and 
    * a file format version as interpretation scheme. 
    *   
    * @param input <code>InputStream</code> input stream delivering encrypted data
    *        from a PWS file
    * @param cipher decryption cipher        
    * @param format the file format version
    * @param hmac <code>PwsChecksum</code> that is updated with resulting field values 
    *        as reading progresses (this serves building up the verification checksum of the PWS file);
    *        may be <b>null</b> 
    * @throws IOException
    */
   public RawFieldReader ( InputStream input, PwsCipher cipher, int format, PwsChecksum hmac  ) throws IOException
   {
      blockStream = new BlockInputStream( input, cipher );
      init( blockStream, format, hmac );
   }

   private void init ( PwsBlockInputStream bs, int format, PwsChecksum hmac ) throws IOException
   {
      blockStream = bs;
      blocksize = blockStream.getBlockSize();
      fileVersion = format;
      this.hmac = hmac;
      readNextRawField();
   }
   
   /* 
    * Overridden: @see org.jpws.pwslib.data.PwsRawFieldReader#getBlocksize()
    */
   public int getBlocksize ()
   {
      return blocksize;
   }
   
   /* 
    * Overridden: @see org.jpws.pwslib.data.PwsRawFieldReader#close()
    */ 
   public void close ()
   {
      nextField = null;
      blockStream = null;
   }

   /* 
    * Overridden: @see org.jpws.pwslib.data.PwsRawFieldReader#hasNext()
    */
   public boolean hasNext ()
   {
      return nextField != null;
   }

   /* 
    * Overridden: @see org.jpws.pwslib.data.PwsRawFieldReader#next()
    */
   public Object next ()
   {
      PwsRawField field;
      
      if ( (field = nextField) != null )
      {
         try { readNextRawField(); }
         catch ( Exception e )
         {
            e.printStackTrace();
            throw new IllegalStateException( "Exception: " + e );
         }
         return field;
      }
      else
      {
         close();
         throw new NoSuchElementException();
      }
   }

   /* 
    * Overridden: @see org.jpws.pwslib.data.PwsRawFieldReader#remove()
    */
   public void remove ()
   {
      throw new UnsupportedOperationException();
   }
   
   public static int rawCount;

   private void readNextRawField () throws IOException
   {
      // clear instance member
      nextField = null;

      // break if no more data in block stream
      if ( !blockStream.isAvailable() )
         return;

      // create "next" raw field
      nextField = new PwsRawField( blockStream, fileVersion );

      // update reading checksum
      if ( hmac != null )
         hmac.update( nextField );

      // update counter
      rawCount++;
   }  // readNextRawField 

}