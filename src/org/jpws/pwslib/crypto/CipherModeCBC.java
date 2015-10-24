/*
 *  CipherModeCBC in org.sundra.crypto
 *  file: CipherModeCBC.java
 * 
 *  Project SUNDRA
 *  @author Wolfgang Keller
 *  Created 17.07.2006
 *  Version
 * 
 *  Copyright (c) 2006 by Wolfgang Keller, Munich, Germany
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

import org.jpws.pwslib.global.Util;

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
   public static final int ENCRYPTING = 1;
   public static final int DECRYPTING = 2;

   private PwsCipher cipher;
   private int blocksize;
   private int direction;
   private byte[] vector;
   private byte[] cbuf;

/**
 * Creates a CBC mode cipher from the parameter cipher and the
 * given initialisation vector.
 * 
 * @param ci block-cipher in ECB mode 
 * @param iv initialisation vector data (with a minimum length of <code>ci</code> blocksize)
 * @throws IllegalArgumentException
 */
public CipherModeCBC ( PwsCipher ci, byte[] iv )
{
   if ( ci instanceof CipherModeCBC )
      throw new IllegalArgumentException( "input cipher must be ecb-cipher, is cbc" );
   
   if ( (blocksize = ci.getBlockSize()) == 0 )
      throw new IllegalArgumentException( "input cipher must be block-cipher" );
   
   if ( iv.length < blocksize )
      throw new IllegalArgumentException( "illegal IV data length" );
   
   cipher = ci;
   vector = Util.arraycopy( iv, blocksize );
   cbuf = new byte[ blocksize ];
}

/**
 * Creates a CBC mode cipher from the parameter cipher and
 * a block of zeros as initialization vector.
 * 
 * @param ci ECB mode block-cipher
 */
public CipherModeCBC ( PwsCipher ci )
{
   this( ci, new byte[ ci.getBlockSize() ] );
}

@Override
public byte[] decrypt ( byte[] buffer )
{
   return decrypt( buffer, 0, buffer.length );
}

@Override
public synchronized byte[] decrypt ( byte[] buffer, int start, int length )
{
   byte[] buf1, plain, result;
   int i, loops, pos;
   
   if ( direction == ENCRYPTING )
      throw new IllegalStateException( "mismatching crypting direction" );
   
   direction = DECRYPTING;
   
   if ( length % blocksize != 0 )
      throw new IllegalArgumentException( "illegal data length" );
   
   plain = null;
   result = new byte[ length ];
   loops = length / blocksize;
   pos = 0;
   for ( i = 0; i < loops; i++ ) {
      // extract data for this loop from user buffer
      System.arraycopy( buffer, start + pos, cbuf, 0, blocksize );
      
      // decrypt user block and XOR it with vector
      buf1 = cipher.decrypt( cbuf );
      plain = Util.XOR_buffers( buf1, vector );

      // save results of this decryption loop
      System.arraycopy( plain, 0, result, pos, blocksize );
      Util.destroyBytes( plain );
      
      // create next vector
      vector = Util.arraycopy( cbuf );

      // propagate pointer
      pos += blocksize;
   }
   
   return result;
}  // decrypt

@Override
public byte[] encrypt ( byte[] buffer )
{
   return encrypt( buffer, 0, buffer.length );
}

@Override
public synchronized byte[] encrypt ( byte[] buffer, int start, int length )
{
   byte[] buf1=null, buf2, result;
   int i, loops, pos;
   
   if ( direction == DECRYPTING )
      throw new IllegalStateException( "mismatching crypting direction" );
   
   direction = ENCRYPTING;
   
   if ( length % blocksize != 0 )
      throw new IllegalArgumentException( "illegal data length" );
   
   result = new byte[ length ];
   loops = length / blocksize;
   pos = 0;
   for ( i = 0; i < loops; i++ ) {
      // extract data for this loop from user buffer
      System.arraycopy( buffer, start + pos, cbuf, 0, blocksize );
      
      // XOR user block with vector and encrypt result 
      buf1 = Util.XOR_buffers( cbuf, vector );
      buf2 = cipher.encrypt( buf1 );

      // save results of this encryption loop
      System.arraycopy( buf2, 0, result, pos, blocksize );
      vector = buf2;

      // propagate pointer
      pos += blocksize;
   }
   
   Util.destroyBytes(cbuf);
   return result;
}  // encrypt

@Override
public int getBlockSize ()
{
   return blocksize;
}

/** The cipher operation direction. May be <code>ENCRYPTING</code> or <code>DECRYPTING</code>
 *  or 0 if not yet determined. (The first cipher operation determines the direction.) 
 *  */  
public int getDirection ()
{
   return direction;
}

/**
 * Returns the cipher's CBC encryption vector as a direct reference.
 * @return byte[] of cipher's blocksize length
 */
public byte[] getVector ()
{
   return vector;
}

@Override
public String getName() {
	return cipher.getName().concat(" mode CBC");
}

}
