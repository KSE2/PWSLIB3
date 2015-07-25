/*
 *  BlowfishCipher in org.jpws.pwslib.crypto
 *  file: BlowfishCipher.java
 * 
 *  Project JPasswords
 *  @author Wolfgang Keller
 *  Created 08.08.2004
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
 * This class allows to instantiate Twofish ciphers of different operation
 * modi, conforming to the <code>PwsCipher</code> interface.
 * Available are "ECB" and "CBC" modi. Crypting methods of this class are 
 * synchronized. 
 * 
 * @since 2-0-0
 */
public class TwofishCipher implements PwsCipher
{
   private PwsCipher   ciph;
   
   /**
    *  Creates a Twofish ECB cipher with a sound random key (256 bit). 
    */
   public TwofishCipher ()
   {
      ciph = new TwofishECB();
   }

   /**
    *  Creates a Twofish ECB cipher with specified key material.
    *  @param key the key material
    */
   public TwofishCipher ( byte[] key )
   {
      ciph = new TwofishECB( key );
   }

   /**
    *  Creates a Twofish CBC cipher with specified key material and CBC IV value.
    *  @param key the key material
    *  @param init the CBC IV value (minimum 16 bytes) 
    */
   public TwofishCipher ( byte[] key, byte[] init )
   {
      ciph = new CipherModeCBC( new TwofishECB( key ), init );
   }

   public synchronized byte[] decrypt ( byte[] buffer )
   {
      return ciph.decrypt( buffer, 0, buffer.length );
   }

   public synchronized byte[] encrypt ( byte[] buffer )
   {
      return ciph.encrypt( buffer, 0, buffer.length );
   }

   public synchronized byte[] decrypt ( byte[] buffer, int start, int length )
   {
      return ciph.decrypt( buffer, start, length );
   }
   public synchronized byte[] encrypt ( byte[] buffer, int start, int length )
   {
      return ciph.encrypt( buffer, start, length );
   }
   
   public int getBlockSize ()
   {
      return ciph.getBlockSize();
   }
   
   public synchronized static boolean self_test() 
   {
      return Twofish.self_test();
   }

}
