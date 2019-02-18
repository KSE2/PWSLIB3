/*
 *  File: PwsCipher.java
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
 * Interface for a cryptographic cipher algorithm as used in PWSLIB.
 * PWSLIB uses block ciphers of different block sizes and operation modi.
 * Implementing classes generally should synchronise the methods of this 
 * interface!
 */
public interface PwsCipher
{
   public static final int ENCRYPTING = 1;
   public static final int DECRYPTING = 2;

   /**
    *  Decrypts a buffer of data and returns the result in a new buffer. 
    *  Input buffer data will not be altered.
    * 
    * @param buffer byte[] encrypted data; length must be an integer multiple
    *        of the cipher's blocksize
    * @return byte[] decrypted data block (same length as <code>buffer</code>) 
    * @throws IllegalStateException if a DIRECTION failure occurs 
    */
   public byte[] decrypt ( byte[] buffer );

   /**
    *  Decrypts a section of a user data buffer and returns the result in a new
    *  buffer. The input buffer data will not be altered.
    * 
    * @param buffer byte[] encrypted data 
    * @param start int start offset in the buffer
    * @param length int length of the encrypted section; must be an integer
    *        multiple of the cipher's blocksize
    * @return byte[] decrypted data block of length <code>length</code> 
    * @throws IllegalStateException if a DIRECTION failure occurs 
    */
   public byte[] decrypt ( byte[] buffer, int start, int length );

   /**
    *  Decrypts a section of an input buffer and returns the result in a section
    *  of the given output block. 
    *  The input buffer data will not be altered.
    * 
    * @param input byte[] cipher-text data; length must be an integer multiple 
    *        of the cipher's blocksize
    * @param inOffs int start offset in input
    * @param output byte[] plain-text data block 
    * @param inOffs int start offset in output
    * @param length int length of data to be translated (bytes)
    * @throws IllegalStateException if a DIRECTION failure occurs 
    */
   public void decrypt ( byte[] input, int inOffs, byte[] output, int outOffs, int length );

   /**
    *  Encrypts a buffer of data and returns the result in a new buffer. 
    *  The input buffer data will not be altered.
    * 
    * @param buffer byte[] cleartext data; length must be an integer multiple 
    *        of the cipher's blocksize
    * @return byte[] encrypted data block (same length as <code>buffer</code>) 
    * @throws IllegalStateException if a DIRECTION failure occurs 
    */
   public byte[] encrypt ( byte[] buffer );

   /**
    *  Encrypts a section of an input buffer and returns the result in a section
    *  of the given output block. 
    *  The input buffer data will not be altered.
    * 
    * @param input byte[] clear-text data; length must be an integer multiple 
    *        of the cipher's blocksize
    * @param inOffs int start offset in input
    * @param output byte[] encrypted data block (same length as <code>buffer</code>) 
    * @param outOffs int start offset in output
    * @param length int length of data to be translated (bytes)
    * @throws IllegalStateException if a DIRECTION failure occurs 
    */
   public void encrypt ( byte[] input, int inOffs, byte[] output, int outOffs, int length );

   /**
    *  Encrypts a section of a user data buffer and returns the result in a new
    *  buffer. The input buffer data will not be altered.
    * 
    * @param buffer byte[] cleartext data 
    * @param start int start offset in the buffer of the source cleartext block
    * @param length int length of the cleartext block; must be an integer
    *        multiple of the cipher's blocksize
    * @return byte[] encrypted data block of length <code>length</code> 
    * @throws IllegalStateException if a DIRECTION failure occurs 
    */
   public byte[] encrypt ( byte[] buffer, int start, int length );

   /** Returns the blocksize of this cipher or 0 if this cipher is not a 
    *  block cipher.
    *  
    *  @return int blocksize
    */
   public int getBlockSize ();
   
   /** The name expression for this cipher for human information.
    * 
    * @return String cipher name
    */
   public String getName ();
   
}
