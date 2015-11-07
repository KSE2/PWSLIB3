package org.jpws.pwslib.data;

import java.io.IOException;

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
   public interface PwsRawFieldWriter 
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