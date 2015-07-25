/*
 *  PwsCipher in org.jpws.pwslib.global
 *  file: PwsCipher.java
 * 
 *  Project JPasswords
 *  @author Wolfgang Keller
 *  Created 07.08.2004
 *  Version 
 * 
 *  Copyright (c) 2005 by Wolfgang Keller, Munich, Germany
 * 
 This program is not freeware software but copyright protected to the author(s)
 stated above. However, you can use, redistribute and/or modify it under the terms 
 of the GNU General Public License as published by the Free Software Foundation, 
 version 2 of the License.

 This program is distributed in the hope that it will be useful, but WITHOUT
 ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

 You should have received a copy of the GNU General Public License along with
 this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 Place - Suite 330, Boston, MA 02111-1307, USA, or go to
 http://www.gnu.org/copyleft/gpl.html.
 */

package org.jpws.pwslib.crypto;


/**
 * Interface for a cryptographic algorithm along the Block Cipher blend.
 * Initialization is taken care of along their individual requirements of 
 * implementing classes. These classes also have to synchronize the methods of
 * this interface!
 */
public interface PwsCipher
{
   /**
    *  Decrypts a buffer of data. The input buffer data will not be altered.
    * 
    * @param buffer encrypted data; length must be an integer multiple of the
    *        cipher's blocksize;  0 allowed
    * @return the decrypted data array (same length as <code>buffer</code>) 
    */
   public byte[] decrypt ( byte[] buffer );

   /**
    *  Decrypts a section of a user data buffer. The input buffer data will not 
    *  be altered.
    * 
    * @param buffer encrypted data 
    * @param start the start offset in the buffer of the source ciphertext block
    * @param length the length of the ciphertext block; must be an integer
    *        multiple of the cipher's blocksize; 0 allowed
    * @return the decrypted data array of length <code>length</code> 
    */
   public byte[] decrypt ( byte[] buffer, int start, int length );

   /**
    *  Encrypts a buffer of data. The input buffer data will not be altered.
    * 
    * @param buffer cleartext data; length must be an integer multiple of the
    *        cipher's blocksize; 0 allowed
    * @return the encrypted data array (same length as <code>buffer</code>) 
    */
   public byte[] encrypt ( byte[] buffer );

   /**
    *  Encrypts a section of a user data buffer. The input buffer data will not 
    *  be altered.
    * 
    * @param buffer cleartext data 
    * @param start the start offset in the buffer of the source cleartext block
    * @param length the length of the cleartext block; must be an integer
    *        multiple of the cipher's blocksize; 0 allowed
    * @return the encrypted data array of length <code>length</code> 
    */
   public byte[] encrypt ( byte[] buffer, int start, int length );

   /** Returns the blocksize of this cipher or 0 if this cipher is not a 
    *  block-cipher. */
   public int getBlockSize ();
}
