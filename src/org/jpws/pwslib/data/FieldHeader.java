/*
 *  File: FieldHeader.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created ?
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

import java.io.StreamCorruptedException;

import org.jpws.pwslib.global.Global;
import org.jpws.pwslib.global.Util;

/**
 * Package class to represent a field HEADERBLOCK of the database format description.
 */
class FieldHeader
{
   /** Length L of the active data value of a field */
   public int length;
   
   /** Field type identifier */
   public int type;
   
   /** Number of data blocks to be read after header block */
   public int blocks;
   
   private int segLen;	 // length of header block data segment
   
   private byte[] block;
   
   /**  Creates a header block by interpreting a data block of the PWS file. 
    *
    *  @param block file data block (of version dependent length)
    * @throws StreamCorruptedException 
    */
   public FieldHeader ( byte[] block, int format ) throws StreamCorruptedException {
      int remLength; // remaining data length in data blocks 
      int blocklen = block.length;
      this.block = block;
      
      // read data length value
      length = Util.readIntLittle( block, 0 );
      if ( length < 0 ) {
         throw new StreamCorruptedException("illegal negative length value: " + length);
      }
      
      // read type value
      type = (int)block[4] & 0xff;
      
      // determine length of header owned user data (format 3 only)
      if ( format == Global.FILEVERSION_3 ) {
         segLen = blocklen - 5;
         remLength = Math.max(0, length - segLen);
      } else {
         remLength = length;
      }

      // determine number of blocks following
      blocks = remLength / blocklen;
      if ( remLength % blocklen > 0 ||
           (format < Global.FILEVERSION_3 & remLength == 0) ) {
         blocks++;
      }
   }  // constructor
   
   /** Writes the header's user-data segment into the given buffer address.
    * (Format 3 only)
    *  
    * @param buffer byte[] target data buffer
    * @param start int target offset
    * @return int number of bytes written
    */
   public int writeDataSegment ( byte[] buffer, int start ) {
	   if ( segLen == 0 ) return 0;
	   int writeLen = Math.min(length, segLen);
       System.arraycopy(block, 5, buffer, start, writeLen);
       return writeLen;
   }
   
}