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

import kse.utilclass.misc.Util;

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
   private boolean consumed;
   /** collective operation data vector; holds in sequence (blocksize each):
    * vector, cbuf, encvec */
   private byte[] opdat;
   private int cbufOff, encvecOff;

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
   opdat = Util.arraycopy( iv, 3 * blocksize );
   cbufOff = blocksize;
   encvecOff = 2 * blocksize;
}

/**
 * Creates a CFB mode cipher from the parameter cipher and
 * a block of zeros as initialisation vector.
 * 
 * @param ci block-cipher
 */
public CipherModeCFB ( PwsCipher ci ) {
   this( ci, new byte[ ci.getBlockSize() ] );
}

public byte[] decrypt ( byte[] buffer ) {
   return decrypt( buffer, 0, buffer.length );
}

public byte[] decrypt ( byte[] buffer, int start, int length ) {
   byte[] result = new byte[ length ];
   decrypt( buffer, start, result, 0, length );
   return result;
}

@Override
public synchronized void decrypt (byte[] input, int inOffs, byte[] output, int outOffs, int length) {
   if ( consumed )
	  throw new IllegalStateException( "cipher is consumed (vector invalid)" );
   
   if ( direction == ENCRYPTING )
      throw new IllegalStateException( "mismatching crypting direction" );
   direction = DECRYPTING;

   // calculate block looping and consumed status 
   int loops = length / blocksize;
   int remains = length % blocksize;
   if ( remains != 0 ) {
	   consumed = true;
	   loops++;
   }

   int pos = 0;
   int clen = blocksize;
   for ( int i = 0; i < loops; i++ ) {
	  // adjust data copy length for last loop (if consumed)
	  if ( consumed && i == loops-1 ) {
		  clen = remains;  
	  }
			  
      // extract data for this loop from user buffer, user data --> cbuf
      System.arraycopy( input, inOffs+pos, opdat, cbufOff, clen );
      
      // encrypt vector and XOR with user block,  vector --> encvec
      cipher.encrypt( opdat, 0, opdat, encvecOff, blocksize );
      for ( int j = 0; j < blocksize; j++ ) {
    	  opdat[encvecOff+j] ^= opdat[cbufOff+j]; 
      }

      // save results of this decryption loop, encvec --> user data
      System.arraycopy( opdat, encvecOff, output, outOffs+pos, clen );

      // create next vector  --> vector
      System.arraycopy( opdat, cbufOff, opdat, 0, blocksize );

      // propagate pointer
      pos += blocksize;
   }
	
//   Util.destroyBytes( encvec );
}  // decrypt

public byte[] encrypt ( byte[] buffer ) {
   return encrypt( buffer, 0, buffer.length );
}

public byte[] encrypt ( byte[] buffer, int start, int length ) {
   byte[] result = new byte[ length ];
   encrypt( buffer, start, result, 0, length );
   return result;
}

@Override
public synchronized void encrypt (byte[] input, int inOffs, byte[] output, int outOffs, int length) {
   if ( consumed )
	  throw new IllegalStateException( "cipher is consumed (vector invalid)" );
		   
   if ( direction == DECRYPTING )
      throw new IllegalStateException( "mismatching crypting direction" );
   direction = ENCRYPTING;
   
   // calculate block looping and consumed status 
   int loops = length / blocksize;
   int remains = length % blocksize;
   if ( remains != 0 ) {
	   consumed = true;
	   loops++;
   }

   int pos = 0;
   int clen = blocksize;
   for ( int i = 0; i < loops; i++ ) {
      // adjust data copy length for last loop (if consumed)
	  if ( consumed && i == loops-1 ) {
		  clen = remains;  
	  }
				  
      // extract data for this loop from user buffer, user data --> cbuf
      System.arraycopy( input, inOffs+pos, opdat, cbufOff, clen );
      
      // encrypt vector and XOR with user block, vector --> encvec  
      cipher.encrypt( opdat, 0, opdat, encvecOff, blocksize );
      for ( int j = 0; j < blocksize; j++ ) {
    	  opdat[encvecOff+j] ^= opdat[cbufOff+j]; 
      }

      // save results of this encryption loop, encvec --> user data
      System.arraycopy( opdat, encvecOff, output, outOffs+pos, clen );

      // build next vector, encvec --> vector
      System.arraycopy( opdat, encvecOff, opdat, 0, blocksize );

      // propagate pointer
      pos += blocksize;
   }
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

/** If true this cipher cannot be used any more as its vector has rendered
 * invalid. The crypting methods will throw exceptions.
 *  
 * @return boolean true = cipher is invalid, false = cipher is valid
 */
public boolean isConsumed () {
	return consumed;
}

/**
 * Returns the cipher's encryption vector in a copy.
 * 
 * @return byte[] of cipher's blocksize length
 */
public byte[] getVector () {
   return Util.arraycopy(opdat, 0, blocksize);
}

@Override
public String getName() {
	return cipher.getName().concat(" mode CFB");
}

}
