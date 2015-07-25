package org.jpws.pwslib.data;

import org.jpws.pwslib.global.Global;
import org.jpws.pwslib.global.Util;

/**
 * Package class to represent a HEADERBLOCK of the database format description.
 * @since 2-0-0
 */
class FieldHeader
{
   /** Length L of the active data value of a field */
   public int length;
   
   /** Field type identifier */
   public int type;
   
   /** Number of data blocks to be read after header block */
   public int blocks;
   
   /** Field first data segment (V3 files only) */ 
   public byte[] data; 

   /**  Creates a header block by interpreting a data block of the PWS file. 
    *
    *  @param block file data block (of version dependent length)
    */
   public FieldHeader ( byte[] block, int format )
   {
      int remLength; // remaining data length in data blocks 
      int segLen;    // length of header block data capacity (segment)
      
      long v = Util.readLongLittle( block, 0 );
      length = (int)v;
      if ( length < 0 )
         length = Integer.MAX_VALUE;
      type = (int)(v >>> 32) & 0xff;
      segLen = block.length - 5;
      
      if ( format == Global.FILEVERSION_3 )
      {
         data = Util.arraycopy( block, 5, Math.min( segLen, length ) );
         remLength = Math.max( 0, length - segLen );
      }
      else
         remLength = length;
      
      blocks = remLength / block.length;
      if ( remLength % block.length > 0 ||
           (format < Global.FILEVERSION_3 & remLength == 0) )
         blocks++;
   }  // constructor
   
   /** Erases all data from this header and reset its values to zero/null. */
   public void clear ()
   {
      Util.destroyBytes( data );
      data = null;
      length = 0;
      type = 0;
      blocks = 0;
   }
   
}