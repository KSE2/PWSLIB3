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

import org.jpws.pwslib.global.Util2;

/**
 * This class allows to instantiate Blowfish ciphers of different operation
 * modi, conforming to the <code>PwsCipher</code> interface.
 * Available are "ECB" and "CBC" modi. Crypting methods of this class are 
 * synchronised. 
 * 
 * <p>NOTE that the Blowfish ciphers supplied here are a special version
 * for the PWS file format and, as is, not compatible with Schneier's
 * regular Blowfish algorithm. 
 */

public class BlowfishCipher implements PwsCipher
{
   private PwsCipher   ciph;
   
   /**
    *  Creates a Blowfish ECB cipher with a sound random key. 
    */
   public BlowfishCipher () {
      ciph = new BlowfishECB2( Util2.getCryptoRand().nextBytes( 48 ) );
   }

   /**
    *  Blowfish ECB cipher with specified key source.
    *  @param key the key material
    */
   public BlowfishCipher ( byte[] key ) {
      ciph = new BlowfishECB2( key );
   }

   /**
    *  Blowfish CBC cipher with specified key source and CBC IV value.
    *  
    *  @param key the key material
    *  @param init the CBC IV value (minimum 8 bytes) 
    */
   public BlowfishCipher ( byte[] key, byte[] init ) {
      ciph = new CipherModeCBC( new BlowfishECB2( key ), init );
   }

   @Override
   public synchronized byte[] decrypt ( byte[] buffer ) {
      return decrypt( buffer, 0, buffer.length );
   }

   @Override
   public synchronized byte[] encrypt ( byte[] buffer ) {
      return encrypt( buffer, 0, buffer.length );
   }

   @Override
   public synchronized byte[] decrypt ( byte[] buffer, int start, int length ) {
      return ciph.decrypt( buffer, start, length );
   }
   
   @Override
   public synchronized byte[] encrypt ( byte[] buffer, int start, int length ) {
      return ciph.encrypt( buffer, start, length );
   }
   
	@Override
	public synchronized void decrypt(byte[] input, int inOffs, byte[] output, int outOffs, int length) {
		ciph.decrypt(input, inOffs, output, outOffs, length);
	}

	@Override
	public synchronized void encrypt(byte[] input, int inOffs, byte[] output, int outOffs, int length) {
		ciph.encrypt(input, inOffs, output, outOffs, length);
	}

   @Override
   public int getBlockSize () {
      return ciph.getBlockSize();
   }
   
   public static boolean self_test() {
      return BlowfishECB2.selfTest();
   }

	@Override
	public String getName() {
		return ciph.getName();
	}

}
