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

import org.jpws.pwslib.global.Util2;

import kse.utilclass.misc.Log;
import kse.utilclass.misc.Util;

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
	this( Util2.getCryptoRand().nextBytes( 32 ) );
}

/**
 * Creates a Twofish ECB cipher with the given user key material.
 * 
 * @param key byte[] user key material (8, 16, 24 or 32 bytes)
 * @throws IllegalArgumentException if key is invalid (length)
 */
public TwofishECB ( byte[] key ) {
   Log.log(3, "(TwofishECB) init with key-length " + (key.length * 8) + " bit");
   try { 
	   sk = Twofish.makeKey( key ); 
   } catch (InvalidKeyException e) { 
	   throw new IllegalArgumentException("Invalid key material / " + e.toString()); 
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
	this( Util.arraycopy(key, offset, length) );
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
public byte[] decrypt ( byte[] buffer, int start, int length ) {
   byte[] result = new byte[ length ];
   decrypt( buffer, start, result, 0, length );
   return result;
}

@Override
public byte[] encrypt ( byte[] buffer, int start, int length ) {
   byte[] result = new byte[ length ];
   encrypt( buffer, start, result, 0, length );
   return result;
}

@Override
public void decrypt (byte[] input, int inOffs, byte[] output, int outOffs, int length) {
   if ( length % Twofish.BLOCK_SIZE > 0 )
      throw new IllegalArgumentException( "illegal data blocklength" );
	   
   int loops = length / Twofish.BLOCK_SIZE;
   int delta = 0;
   for ( int i = 0; i < loops; i++ ) {
      Twofish.blockDecrypt( input, inOffs+delta, output, outOffs+delta, sk );
      delta += Twofish.BLOCK_SIZE;
   }
}

@Override
public void encrypt (byte[] input, int inOffs, byte[] output, int outOffs, int length) {
   if ( length % Twofish.BLOCK_SIZE > 0 )
      throw new IllegalArgumentException( "illegal data blocklength" );
		   
   int loops = length / Twofish.BLOCK_SIZE;
   int delta = 0;
   for ( int i = 0; i < loops; i++ ) {
      Twofish.blockEncrypt( input, inOffs+delta, output, outOffs+delta, sk );
      delta += Twofish.BLOCK_SIZE;
   }
}

@Override
public String getName() {
	return CIPHER_NAME;
}

@Override
public int getBlockSize () {
   return Twofish.BLOCK_SIZE;
}

}
