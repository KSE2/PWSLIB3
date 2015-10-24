/*
 *  file: UUID.java
 * 
 *  Project JPasswords
 *  @author Wolfgang Keller
 *  Created 07.08.2005
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

package org.jpws.pwslib.global;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.Serializable;

import org.jpws.pwslib.crypto.SHA1;


/**
 * A naive but fairly effective implementation of a UUID class.
 * <p>"UUID" is a "Universal Unique Identifier". A UUID is meant to occur
 * universally unique, within the limits of computational probability.
 * By convention it is constructed as a 16 byte bit-array. This implementation
 * uses time, random bytes and SHA1 to reach at a qualified unique value.
 * 
 * @author Kevin Preece
 * @author Wolfgang Keller
 */
public final class UUID implements Cloneable, Comparable, Serializable
{
	private final byte []		uidValue	= new byte[ 16 ];
	private       int          hashcode;

	/**
	 * Constructs this object as a a new random UUID.
    * 
    * @throws IllegalStateException if creation fails
    *         (should happen only on out of memory) 
	 */
	public UUID()
	{
	   ByteArrayOutputStream bstream;
      DataOutputStream stream;
      SHA1 sha;
      byte[]   result;
      long		time;
		int		i;

		sha = new SHA1();
      bstream = new ByteArrayOutputStream();
      stream = new DataOutputStream( bstream );
      try {
   		time = System.currentTimeMillis();
//System.out.println( "UUID time value: " + new Date( time ).toGMTString() );      
//System.out.println( "System time value: " + new Date( System.currentTimeMillis() ).toGMTString() );      

         stream.writeLong( time );
         for ( i = 0; i < 8; i++ )
            stream.writeByte( Util.nextRandByte() );
         stream.close();
         
         sha.update( bstream.toByteArray() );
         sha.finalize();
         result = sha.getDigest();
         System.arraycopy( result, 0, uidValue, 0, uidValue.length );
         hashcode = Util.arrayHashcode(uidValue);
//System.out.println( "UUID value: " + toString() );      
      }

      catch ( Exception e )
      {        
         e.printStackTrace();
         throw new IllegalStateException("corrupted UUID creation");
      }
	}  // constructor

	/**
	 * Constructs the UUID from a 16 byte array parameter (identical).
	 *   
	 * @param uuid the 16 bytes array to use as the UUID
     * @throws IllegalArgumentException
	 */
	public UUID( byte [] uuid )
	{
		if ( uuid == null || uuid.length != uidValue.length )
			throw new IllegalArgumentException();

      System.arraycopy( uuid, 0, uidValue, 0, uidValue.length );
      hashcode = Util.arrayHashcode(uidValue);
	}  // constructor

    /**
     * Constructs the UUID from a hexadecimal text representation of
     * a 16 byte UUID value.
     *   
     * @param ids 32 char hexadecimal text value of the UUID
     * @throws IllegalArgumentException
     * @since 0-4-0        
     */
    public UUID( String ids )
    {
       byte[] uuid;
       
       uuid = Util.hexToBytes( ids );
       if ( uuid == null || uuid.length != uidValue.length )
           throw new IllegalArgumentException( "illegal UUID string: " + ids );

       System.arraycopy( uuid, 0, uidValue, 0, uidValue.length );
       hashcode = Util.arrayHashcode(uidValue);
    }  // constructor

	/**
	 * Compares this <code>UUID</code> object to another one and determines
    * equality of both. 
	 * 
	 * @param obj a <code>UUID</code> object to compare to
    * @return <b>true</b> if and only if all bytes of the 16 byte UUID value 
    *         are equal
	 */
	public boolean equals( Object obj )
	{
      if ( obj == null || !(obj instanceof UUID) )
         return false;
      
      return Util.equalArrays( uidValue, ((UUID)obj).uidValue );
	}

	/** A hashcode coherent with <code>equals()</code>.
	 */ 
   public int hashCode()
   {
      return hashcode;
   }

   //  * @since 2-1-0
	public int compareTo ( Object o )
   {
       UUID obj = (UUID)o;
       int i = 0;
       while ( i < uidValue.length && uidValue[ i ] == obj.uidValue[ i ] )
          i++;
       if ( i == uidValue.length )
          return 0;
       return uidValue[ i ] - obj.uidValue[ i ];
   }

   /**
	 * Returns a byte array containing a copy of the 16 byte value
    * of this UUID.
	 * 
	 * @return byte array (length 16)
	 */
	public byte [] getBytes()
	{
		return (byte[]) uidValue.clone();
	}

    /**
     * Returns a hexadezimal representation of the 16 byte value
     * of this UUID.
     * @return String
     */
    public String toHexString ()
    {
       return Util.bytesToHex( uidValue );
    }
    
   /**
    * Makes a deep clone of this UUID object.
    */
   public Object clone ()
   {
      try {  return super.clone();  }
      catch ( CloneNotSupportedException e )
      {
         return null;
      }
   }
   
	/**
	 * Converts this UUID into human-readable form.  The string has the format:
	 * {01234567-89ab-cdef-0123-456789abcdef}.
	 * 
	 * @return <code>String</code> representation of this <code>UUID</code>
	 */
	public String toString()
	{
		return toString( uidValue );
	}

	/**
	 * Converts a <code>uuid</code> value into human-readable form.  The resulting
    * string has the format: {01234567-89ab-cdef-0123-456789abcdef}.
	 * 
	 * @param uuid the 16 byte array to convert; must be of length 16! 
	 * @return <code>String</code> representation of the parameter <code>UUID</code>
    *         value
	 */
	public static String toString( byte[] uuid )
	{
		if ( uuid.length != 16 )
			throw new IllegalArgumentException();

		StringBuffer sb = new StringBuffer();

		sb.append( Util.bytesToHex(uuid, 0, 4) );
		sb.append( '-' );
		sb.append( Util.bytesToHex(uuid, 4, 2) );
		sb.append( '-' );
		sb.append( Util.bytesToHex(uuid, 6, 2) );
		sb.append( '-' );
		sb.append( Util.bytesToHex(uuid, 8, 2) );
		sb.append( '-' );
		sb.append( Util.bytesToHex(uuid, 10, 6) );
		
		return sb.toString();
	}
}
