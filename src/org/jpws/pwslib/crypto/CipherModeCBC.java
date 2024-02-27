/*
 *  File: CipherModeCBC.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 17.07.2006
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

package org.jpws.pwslib.crypto;

import kse.utilclass.misc.Util;

/**
 * This class wraps any ECB mode <code>PwsCipher</code> 
 * and transforms it into a CBC mode cipher. 
 * Crypting methods of this class are synchronised.
 * 
 * <p>CBC mode requires block padding of the cipher text
 * and a base cipher that can both encrypt and decrypt.
 * 
 */
public class CipherModeCBC implements PwsCipher
{
   private final PwsCipher cipher;
   private final int blocksize;
   private int direction;
   private byte[] vector;
   private final byte[] cbuf, plain;

/**
 * Creates a CBC mode cipher from the parameter cipher and the
 * given initialisation vector. If the vector is longer than the cipher's
 * blocksize, only the first blocksize bytes are used.
 * 
 * @param ci <code>PwsCipher</code> block-cipher in ECB mode 
 * @param iv byte[] initialisation vector (minimum length of 
 *        <code>ci</code> blocksize)
 * @throws IllegalArgumentException
 */
public CipherModeCBC ( PwsCipher ci, byte[] iv ) {
   if ( ci instanceof CipherModeCBC )
      throw new IllegalArgumentException( "input cipher must be ECB-cipher, is CBC" );
   
   if ( (blocksize = ci.getBlockSize()) == 0 )
      throw new IllegalArgumentException( "input cipher must be block-cipher" );
   
   if ( iv.length < blocksize )
      throw new IllegalArgumentException( "illegal IV data length" );
   
   cipher = ci;
   vector = Util.arraycopy( iv, blocksize );
   cbuf = new byte[ blocksize ];
   plain = new byte[ blocksize ];
}

/**
 * Creates a CBC mode cipher from the parameter cipher and
 * a block of zeros as initialisation vector.
 * 
 * @param ci ECB mode block-cipher
 */
public CipherModeCBC ( PwsCipher ci ) {
   this( ci, new byte[ ci.getBlockSize() ] );
}

@Override
public byte[] decrypt ( byte[] buffer ) {
   return decrypt( buffer, 0, buffer.length );
}

@Override
public synchronized byte[] decrypt ( byte[] buffer, int start, int length ) {
   if ( direction == ENCRYPTING )
      throw new IllegalStateException( "mismatching crypting direction" );
   
   direction = DECRYPTING;
   
   byte[] result = new byte[ length ];
   decrypt( buffer, start, result, 0, length );
   return result;
}  // decrypt

@Override
public void decrypt (byte[] input, int inOffs, byte[] output, int outOffs, int length) {
   if ( direction == ENCRYPTING )
      throw new IllegalStateException( "mismatching crypting direction" );
   
   direction = DECRYPTING;
   
   if ( length % blocksize != 0 )
      throw new IllegalArgumentException( "illegal data length" );
   
   int loops = length / blocksize;
   int pos = 0;
   for ( int i = 0; i < loops; i++ ) {
      // extract data for this loop from user buffer
      System.arraycopy( input, inOffs+pos, cbuf, 0, blocksize );
      
      // decrypt one user block and XOR it with vector
      cipher.decrypt( cbuf, 0, plain, 0, blocksize );
      Util.XOR_buffers2( plain, vector );

      // save results of this decryption loop
      System.arraycopy( plain, 0, output, outOffs+pos, blocksize );
      
      // create next vector
      System.arraycopy( cbuf, 0, vector, 0, blocksize );

      // propagate pointer
      pos += blocksize;
   }
   Util.destroy( plain );
}

@Override
public byte[] encrypt ( byte[] buffer ) {
   return encrypt( buffer, 0, buffer.length );
}

@Override
public synchronized byte[] encrypt ( byte[] buffer, int start, int length ) {
   if ( direction == DECRYPTING )
      throw new IllegalStateException( "mismatching crypting direction" );
   
   direction = ENCRYPTING;
   
   byte[] result = new byte[ length ];
   encrypt( buffer, start, result, 0, length );
   return result;
}  // encrypt

@Override
public void encrypt (byte[] input, int inOffs, byte[] output, int outOffs, int length) {
   if ( direction == DECRYPTING )
      throw new IllegalStateException( "mismatching crypting direction" );
   
   direction = ENCRYPTING;
   
   if ( length % blocksize != 0 )
      throw new IllegalArgumentException( "illegal data length" );
   
   int loops = length / blocksize;
   int pos = 0;
   for ( int i = 0; i < loops; i++ ) {
      // extract data for this loop from user buffer
      System.arraycopy( input, inOffs+pos, cbuf, 0, blocksize );
      
      // XOR user block with vector and encrypt result 
      Util.XOR_buffers2( cbuf, vector );
      cipher.encrypt( cbuf, 0, vector, 0, blocksize );

      // save results of this encryption loop
      System.arraycopy( vector, 0, output, outOffs+pos, blocksize );

      // propagate pointer
      pos += blocksize;
   }
}

@Override
public int getBlockSize () {
   return blocksize;
}

/** The cipher operation direction. May be <code>ENCRYPTING</code> or <code>DECRYPTING</code>
 *  or 0 if not yet determined. (The first cipher operation determines the direction.) 
 *  */  
public int getDirection () {
   return direction;
}

/**
 * Returns the cipher's CBC encryption vector as a direct reference.
 * @return byte[] of cipher's blocksize length
 */
public byte[] getVector () {
   return vector;
}

@Override
public String getName() {
	return cipher.getName().concat(" mode CBC");
}

}
