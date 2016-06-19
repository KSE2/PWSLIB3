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
 * and transforms it into a CFB mode cipher. 
 * Crypting methods of this class are synchronised.
 * 
 * <p>CFB mode has the advantage that the cipher text need not be
 * stored or transmitted in block-padded length. Trailing space
 * of the last block may be filled with zeros (or any other constant)
 * both for cipher- and plain-text. Second advantage
 * is that the base cipher only requires encryption direction.
 * 
 */
public class CipherModeCFB implements PwsCipher
{
   private PwsCipher cipher;
   private final int blocksize;
   private int direction;
   private byte[] vector;
   private final byte[] cbuf;

/**
 * Creates a CFB mode cipher from the parameter cipher and the
 * given initialisation vector.
 * 
 * @param ci block-cipher 
 * @param iv initialisation vector data (with a minimum length of cipher blocksize)
 * @throws IllegalArgumentException
 */
public CipherModeCFB ( PwsCipher ci, byte[] iv ) {
   if ( (blocksize = ci.getBlockSize()) == 0 )
      throw new IllegalArgumentException( "input cipher must be block-cipher" );
   
   if ( iv.length < blocksize )
      throw new IllegalArgumentException( "illegal IV data length, must be ".concat( String.valueOf( blocksize )) );
   
   cipher = ci;
   vector = Util.arraycopy( iv, blocksize );
   cbuf = new byte[ blocksize ];
}

/**
 * Creates a CFB mode cipher from the parameter cipher and
 * a block of zeros as initialization vector.
 * 
 * @param ci block-cipher
 */
public CipherModeCFB ( PwsCipher ci ) {
   this( ci, new byte[ ci.getBlockSize() ] );
}

public byte[] decrypt ( byte[] buffer ) {
   return decrypt( buffer, 0, buffer.length );
}

public synchronized byte[] decrypt ( byte[] buffer, int start, int length ) {
   byte[] buf1, result;
   int i, loops, pos;
   
   if ( direction == ENCRYPTING )
      throw new IllegalStateException( "mismatching crypting direction" );
   direction = DECRYPTING;
   
   if ( length % blocksize != 0 )
      throw new IllegalArgumentException( "illegal data length" );
   
   result = new byte[ length ];
   loops = length / blocksize;
   pos = 0;
   for ( i = 0; i < loops; i++ ) {
      // extract data for this loop from user buffer
      System.arraycopy( buffer, start + pos, cbuf, 0, blocksize );
      
      // encrypt vector and XOR with user block  
      buf1 = cipher.encrypt( vector );
      Util.XOR_buffers2( buf1, cbuf );

      // save results of this decryption loop
      System.arraycopy( buf1, 0, result, pos, blocksize );
      Util.destroyBytes( buf1 );

      // create next vector
      System.arraycopy( cbuf, 0, vector, 0, blocksize );

      // propagate pointer
      pos += blocksize;
   }
   
   return result;
}  // decrypt

public byte[] encrypt ( byte[] buffer ) {
   return encrypt( buffer, 0, buffer.length );
}

public synchronized byte[] encrypt ( byte[] buffer, int start, int length ) {
   byte[] buf1, result;
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
      
      // encrypt vector and XOR with user block  
      buf1 = cipher.encrypt( vector );
      Util.XOR_buffers2( buf1, cbuf );

      // save results of this encryption loop
      System.arraycopy( buf1, 0, result, pos, blocksize );
      vector = buf1;

      // propagate pointer
      pos += blocksize;
   }
   
   Util.destroyBytes(cbuf);
   return result;
}  // encrypt

public int getBlockSize () {
   return blocksize;
}

/** The cipher operation direction. May be <code>ENCRYPTING</code> or 
 *  <code>DECRYPTING</code> or 0 if not yet determined. (The first cipher 
 *  operation determines the direction.) 
 */  
public int getDirection () {
   return direction;
}

/**
 * Returns the cipher's encryption vector as a direct reference.
 * 
 * @return byte[] of cipher's blocksize length
 */
public byte[] getVector () {
   return vector;
}

@Override
public String getName() {
	return cipher.getName().concat(" mode CFB");
}

}
