/*
 *  File: PwsChecksum.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 18.10.2006
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

package org.jpws.pwslib.global;

import org.jpws.pwslib.crypto.SHA256;
import org.jpws.pwslib.data.PwsRawField;

/**
 *  A checksum factory conforming to RFC-2104. 
 */

public class PwsChecksum implements Cloneable
{
   private SHA256 sha  = new SHA256();
   private byte[] opad; 
   private byte[] digest;

/**
 * Creates a new HMAC checksum with a given key material.
 *  
 * @param seed byte[] key data up to length 64 bytes
 */
public PwsChecksum ( byte[] seed )
{
   int i, bs;
   byte[] key, ipad;
   
   // verify conditions
   bs = sha.getBlockSize();
   if ( seed.length > bs )
      throw new IllegalArgumentException("seed length exceeding");

   // prepare ipad and opad
   ipad = new byte[ bs ];
   opad = new byte[ bs ];
   for ( i = 0; i < bs; i++ )
   {      
      ipad[ i ] = 0x36;
      opad[ i ] = 0x5C;
   }
   
   key = Util.arraycopy( seed, bs );
   ipad = Util.XOR_buffers( ipad, key );
   opad = Util.XOR_buffers( opad, key );
   
   // perform initial hash function
   sha.update( ipad );
}

public void update ( byte[] data )
{
   if ( data != null ) 
   {
      update(data, 0, data.length);
   }
}

public void update(byte[] data, int offset, int length) {
   if ( data != null )
   {
//      Log.debug(8, "(PwsChecksum.update) updating (" +
//          length + "): " + Util.bytesToHex(data, offset, length));
      sha.update( data, offset, length );
   }
}

public void update ( PwsRawField raw )
{
   if ( raw != null )
   {
      byte[] buffer = raw.getData();
      update( buffer );
      Util.destroyBytes( buffer );
   }
}

public byte[] digest ()
{
   byte[] dg;
   
   if ( digest == null )
   {
      dg = sha.digest();
      sha.reset();
      sha.update( opad );
      sha.update( dg );
      digest = sha.digest();
   }
   return digest;
}

public Object clone() {
   PwsChecksum sum = null;
   try {
      sum = (PwsChecksum) super.clone();
      if ( digest != null ) {
         sum.digest = Util.arraycopy(digest);
      }
      sum.sha = (SHA256)sha.clone();
   } catch (CloneNotSupportedException e) {
   }
   return sum;
}



}
