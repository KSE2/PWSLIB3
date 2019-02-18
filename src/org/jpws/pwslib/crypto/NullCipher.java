/*
 *  File: NullCipher.java
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
    * This is a neutral cipher with blocksize 8 in the ECB mode, which  
    * performs no alterations to the user data supplied (null operation). 
    * Crypting methods of this class are synchronised. 
 */
public class NullCipher implements PwsCipher
{

   public NullCipher () {
   }

   /** Returns the same content in a new buffer. */
   @Override
   public synchronized byte[] decrypt ( byte[] buffer ) {
      return decrypt( buffer, 0, buffer.length );
   }

   /** Returns the same content in a new buffer. */
   @Override
   public synchronized byte[] encrypt ( byte[] buffer ) {
      return encrypt( buffer, 0, buffer.length );
   }

   
   /** Returns the same content in a new buffer. */
   @Override
   public synchronized byte[] decrypt ( byte[] buffer, int start, int length ) {
      byte[] buf = new byte[ length ];
      System.arraycopy( buffer, start, buf, 0, length );
      return buf;
   }
   
   /** Returns the same content in a new buffer. */
   @Override
   public synchronized byte[] encrypt ( byte[] buffer, int start, int length ) {
      byte[] buf = new byte[ length ];
      System.arraycopy( buffer, start, buf, 0, length );
      return buf;
   }
   
   @Override
   public int getBlockSize () {
      return 8;
   }

	@Override
	public String getName() {
		return "NullCipher";
	}

	@Override
	public void decrypt(byte[] input, int inOffs, byte[] output, int outOffs, int length) {
	     System.arraycopy( input, inOffs, output, outOffs, length );
	}

	@Override
	public void encrypt(byte[] input, int inOffs, byte[] output, int outOffs, int length) {
	     System.arraycopy( input, inOffs, output, outOffs, length );
	}
}
