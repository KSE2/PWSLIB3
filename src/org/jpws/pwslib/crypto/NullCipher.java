/*
 *  NullCipher in org.jpws.pwslib.crypto
 *  file: NullCipher.java
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
    * This is a neutral cipher, assumed to be of the ECB mode, which  
    * performs no alterations to the user data supplied (null operation). 
    * Crypting methods of this class are synchronised. 
 */
public class NullCipher implements PwsCipher
{

   public NullCipher ()
   {
   }

   /** Returns the same content in a different buffer. */
   public synchronized byte[] decrypt ( byte[] buffer )
   {
      return decrypt( buffer, 0, buffer.length );
   }

   /** Returns the same content in a different buffer. */
   public synchronized byte[] encrypt ( byte[] buffer )
   {
      return encrypt( buffer, 0, buffer.length );
   }

   
   
   /** Returns the same content in a different buffer. */
   public synchronized byte[] decrypt ( byte[] buffer, int start, int length )
   {
      byte[] buf;
      
      buf = new byte[ length ];
      System.arraycopy( buffer, start, buf, 0, length );
      return buf;
   }
   
   /** Returns the same content in a different buffer. */
   public synchronized byte[] encrypt ( byte[] buffer, int start, int length )
   {
      byte[] buf;
      
      buf = new byte[ length ];
      System.arraycopy( buffer, start, buf, 0, length );
      return buf;
   }
   
   public int getBlockSize ()
   {
      return 8;
   }
}
