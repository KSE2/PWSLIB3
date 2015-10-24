/*
 *  TwofishECB in org.jpws.pwslib.crypto
 *  file: TwofishECB.java
 * 
 *  Project PWSLIB2
 *  @author Wolfgang Keller
 *  Created 25.09.2006
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

import java.security.InvalidKeyException;

import org.jpws.pwslib.global.Util;

/**
 * Class wrapping a low-level implementation of the Twofish cipher
 * into a <code>PwsCipher</code> of the ECB modus.
 * Methods of this class are not synchronized.
 * 
 */
class TwofishECB implements PwsCipher
{

   private static String CIPHER_NAME = "Twofish";
    
   private Object sk;

/**
 * Creates a Twofish ECB cipher with a reasonable 256-bit random key.
 */   
public TwofishECB () 
{
   try { sk = Twofish.makeKey( Util.getCryptoRand().nextBytes( 32 ) ); }
   catch ( InvalidKeyException e )
   { throw new IllegalStateException( e.toString() ); }
}

public TwofishECB ( byte[] key )
{
   try { sk = Twofish.makeKey( key ); }
   catch ( InvalidKeyException e )
   { throw new IllegalArgumentException( "Invalid key material / " + e.toString() ); }
}

public TwofishECB ( byte[] key, int offset, int length )
{
   byte[] buf;
   
   try {
      buf = new byte[ length ];
      System.arraycopy( key, offset, buf, 0, length );
      sk = Twofish.makeKey( buf ); 
   }
   catch ( InvalidKeyException e )
   { throw new IllegalArgumentException( "Invalid key material / " + e.toString() ); }
}

@Override
public byte[] decrypt ( byte[] buffer, int start, int length )
{
   return crypting( buffer, start, length, true );
}

@Override
public byte[] encrypt ( byte[] buffer, int start, int length )
{
   return crypting( buffer, start, length, false );
}

@Override
public int getBlockSize ()
{
   return Twofish.BLOCK_SIZE;
}

private byte[] crypting ( byte[] buffer, int start, int length, boolean dec )
{
   byte[] one, result;
   int i, pos, loops;
   
   if ( start < 0 | length < 0 | start + length > buffer.length )
      throw new IllegalArgumentException( "illegal parameter setting" );
   if ( length % Twofish.BLOCK_SIZE > 0 )
      throw new IllegalArgumentException( "illegal data blocklength" );
   
   loops = length / Twofish.BLOCK_SIZE;
   result = new byte[ length ];
   one = null;
   pos = start;
   for ( i = 0; i < loops; i++ )
   {
      one = dec ? Twofish.blockDecrypt( buffer, pos, sk ) 
            : Twofish.blockEncrypt( buffer, pos, sk );
      System.arraycopy( one, 0, result, pos - start, Twofish.BLOCK_SIZE );
      Util.destroyBytes(one);
      pos += Twofish.BLOCK_SIZE;
   }
   return result;
}

@Override
public byte[] decrypt ( byte[] buffer )
{
   return decrypt( buffer, 0, buffer.length );
}

@Override
public byte[] encrypt ( byte[] buffer )
{
   return encrypt( buffer, 0, buffer.length );
}

@Override
public String getName() {
	return CIPHER_NAME;
}

}
