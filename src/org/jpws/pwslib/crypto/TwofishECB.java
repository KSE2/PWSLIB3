/*
 *  File: TwofishECB.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 25.09.2006
 * 
 *  Copyright (c) 2006-2015 by Wolfgang Keller, Munich, Germany
 * 
 This program is copyright protected to the author(s) stated above. However, 
 you can use, redistribute and/or modify it for free under the terms of the 
 2-clause BSD-like license given in the document section of this project.  

 This program is distributed in the hope that it will be useful, but WITHOUT
 ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 FOR A PARTICULAR PURPOSE. See the license for more details.
*/

package org.jpws.pwslib.crypto;

import java.security.InvalidKeyException;

import org.jpws.pwslib.global.Util;

/**
 * Class wrapping a low-level implementation of the Twofish cipher
 * into a <code>PwsCipher</code> of the ECB modus.
 * Methods of this class are not synchronised!
 * 
 */
class TwofishECB implements PwsCipher {

   private static String CIPHER_NAME = "Twofish";
    
   private Object sk;

/**
 * Creates a Twofish ECB cipher with a reasonable 256-bit random key.
 */   
public TwofishECB () {
   try { 
	   sk = Twofish.makeKey( Util.getCryptoRand().nextBytes( 32 ) ); 
   } catch ( InvalidKeyException e ) { 
	   throw new IllegalStateException( e.toString() ); 
   }
}

/**
 * Creates a Twofish ECB cipher with the given user key material.
 * 
 * @param key byte[] user key material (8, 16, 24 or 32 bytes)
 * @throws IllegalArgumentException if key is invalid (length)
 */
public TwofishECB ( byte[] key ) {
   try { 
	   sk = Twofish.makeKey( key ); 
   } catch ( InvalidKeyException e ) { 
	   throw new IllegalArgumentException( "Invalid key material / " + e.toString() ); 
   }
}

/**
 * Creates a Twofish ECB cipher with the given user key material.
 * 
 * @param key byte[] user key material 
 * @param offset int start offset in key 
 * @param length int length in key to be used (8, 16, 24 or 32 bytes)
 * @throws IllegalArgumentException if key is invalid (length)
 */
public TwofishECB ( byte[] key, int offset, int length ) {
   try {
	  byte[] buf = new byte[ length ];
      System.arraycopy( key, offset, buf, 0, length );
      sk = Twofish.makeKey( buf ); 
   } catch ( InvalidKeyException e ) { 
	   throw new IllegalArgumentException( "Invalid key material / " + e.toString() ); 
   }
}

@Override
public byte[] decrypt ( byte[] buffer, int start, int length ) {
   return crypting( buffer, start, length, true );
}

@Override
public byte[] encrypt ( byte[] buffer, int start, int length ) {
   return crypting( buffer, start, length, false );
}

@Override
public int getBlockSize () {
   return Twofish.BLOCK_SIZE;
}

private byte[] crypting ( byte[] buffer, int start, int length, boolean dec ) {
   byte[] one, result;
   int i, pos, loops;
   
   if ( start < 0 | length < 0 | start + length > buffer.length )
      throw new IllegalArgumentException( "illegal parameter setting" );
   if ( length % Twofish.BLOCK_SIZE > 0 )
      throw new IllegalArgumentException( "illegal data blocklength" );
   
   loops = length / Twofish.BLOCK_SIZE;
   result = new byte[ length ];
   one = null;
   pos = start;
   for ( i = 0; i < loops; i++ ) {
      one = dec ? Twofish.blockDecrypt( buffer, pos, sk ) 
            : Twofish.blockEncrypt( buffer, pos, sk );
      System.arraycopy( one, 0, result, pos - start, Twofish.BLOCK_SIZE );
      Util.destroyBytes(one);
      pos += Twofish.BLOCK_SIZE;
   }
   return result;
}

@Override
public byte[] decrypt ( byte[] buffer ) {
   return decrypt( buffer, 0, buffer.length );
}

@Override
public byte[] encrypt ( byte[] buffer ) {
   return encrypt( buffer, 0, buffer.length );
}

@Override
public String getName() {
	return CIPHER_NAME;
}

}
