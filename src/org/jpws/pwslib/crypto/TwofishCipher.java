/*
 *  File: BlowfishCipher.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 08.08.2004
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


/**
 * This class allows to instantiate Twofish ciphers of different operation
 * modi, conforming to the <code>PwsCipher</code> interface.
 * Available are "ECB" and "CBC" modi. Crypting methods of this class are 
 * synchronised. The blocksize of this cipher is 16.
 * 
 */
public class TwofishCipher implements PwsCipher
{
   private PwsCipher   ciph;
   
   /**
    *  Creates a Twofish ECB cipher with a sound random key (256 bit). 
    */
   public TwofishCipher () {
      ciph = new TwofishECB();
   }

   /**
    *  Creates a Twofish ECB cipher with specified key material.
    *  
    *  @param key byte[] key material (8, 16, 24 or 32 bytes)
    *  @throws IllegalArgumentException if key length is invalid
    */
   public TwofishCipher ( byte[] key ) {
      ciph = new TwofishECB( key );
   }

   /**
    *  Creates a Twofish CBC cipher with specified key material and CBC IV value.
    *  
    *  @param key byte[]  key material (8, 16, 24 or 32 bytes)
    *  @param init byte[] CBC IV value (minimum 16 bytes) 
    *  @throws IllegalArgumentException if key or IV length is invalid
    */
   public TwofishCipher ( byte[] key, byte[] init ) {
      ciph = new CipherModeCBC( new TwofishECB( key ), init );
   }

   @Override
   public synchronized byte[] decrypt ( byte[] buffer ) {
      return ciph.decrypt( buffer, 0, buffer.length );
   }

   @Override
   public synchronized byte[] encrypt ( byte[] buffer ) {
      return ciph.encrypt( buffer, 0, buffer.length );
   }

   @Override
   public synchronized byte[] decrypt ( byte[] buffer, int start, int length ) {
      return ciph.decrypt( buffer, start, length );
   }

   @Override
   public void decrypt (byte[] input, int inOffs, byte[] output, int outOffs, int length) {
	   ciph.decrypt(input, inOffs, output, outOffs, length);
   }

   @Override
   public synchronized byte[] encrypt ( byte[] buffer, int start, int length ) {
      return ciph.encrypt( buffer, start, length );
   }
   
	@Override
	public void encrypt (byte[] input, int inOffs, byte[] output, int outOffs, int length) {
		ciph.encrypt(input, inOffs, output, outOffs, length);
	}

   @Override
   public int getBlockSize () {
      return ciph.getBlockSize();
   }
   
   public synchronized static boolean self_test() {
      return Twofish.self_test();
   }

	@Override
	public String getName() {
		return ciph.getName();
	}

}
