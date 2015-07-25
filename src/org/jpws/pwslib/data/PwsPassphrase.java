/*
 *  PwsPassphrase in org.jpws.pwslib.data
 *  file: PwsPassphrase.java
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

package org.jpws.pwslib.data;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.IllegalCharsetNameException;
import java.nio.charset.UnsupportedCharsetException;

import org.jpws.pwslib.crypto.PwsCipher;
import org.jpws.pwslib.global.Global;
import org.jpws.pwslib.global.Util;

/**
 * PwsPassphrase represents a sequence of characters which is especially
 * protected against uncoverage through attacking tools analysing the JVM memory.
 * By the design of the class, there is always a crptographic cipher defined
 * for an instance, ensuring that at any time the passphrase value can be
 * both stored encrypted and retrieved decrypted.
 * <p>All functions are "waste clean", i.e. after retrieving a
 * decrypted value from an instance, the returned value is the only object
 * in memory produced by this class and containing a decrypted form of the
 * value. It is then in the responsibility of the caller to handle decrypted
 * values with care. 
 */
public final class PwsPassphrase implements Cloneable
{
   /** The text blocksize required for operations with encrypted data blocks.
    */
   public static final int BLOCKSIZE = PwsFileFactory.PWF_BLOCKSIZE / 2;
   
   private static final byte[] NULLVALUE = new byte[0];
   //DataOutputStream out;
   
   /**  The cipher used to encrypt the passphrase content (sbuf is
    *   always encrypted)
    */
   private PwsCipher cipher;
   
   /** Passphrase buffer; meant to store chars serialized by 2 bytes each.
    *  Must size as an int multiple of BLOCKSIZE * 2 
    */
   private byte[] sbuf;
   
   /** Length in nr. of char; ranges 0..sbuf.length/2 
    */
   private int length;
   
   
/** Constructor for an empty passphrase with default internal encryption cipher.
 */
public PwsPassphrase ()
{
   cipher = Global.getStandardCipher();
   sbuf = NULLVALUE;
}

/** Constructor for an empty passphrase with a specified cipher for internal 
 *  encryption.
 * 
 * @param c a fully initialised <code>PwsCipher</code> 
 */
public PwsPassphrase ( PwsCipher c )
{
   cipher = c;
   sbuf = NULLVALUE;
}

/** Constructor with char array as initial value.
 * 
 * @param passphrase an array of char forming the initial value for this passphrase.  
 *        (Parameter may be destroyed by the caller after construction.)
 */
public PwsPassphrase ( char[] passphrase )
{
   cipher = Global.getStandardCipher();
   setValue( passphrase );
}

/** Constructor with string as initial value.
 * 
 * @param passphrase an array of char forming the initial value for this passphrase.  
 *        (Parameter may be destroyed by the caller after construction.)
 */
public PwsPassphrase ( String passphrase )
{
   cipher = Global.getStandardCipher();
   setValue( passphrase );
}

/** Constructor with byte array as initial value. The byte array is seen as a
 *  sequence of <code>short</code> integer i, each representing <code>(char)i</code>.
 *  The integers are, however, in opposition to the Java tradition, not read
 *  in big-endian but in little-endian manner! 
 * 
 * @param passphrase an array of byte as the initial value for this PP. The length 
 *        of the array must be a multiple of 2; 
 *        (Parameter may be destroyed by the caller after construction.)

public PwsPassphrase ( byte[] passphrase )
{
   byte[] buffer;
   
   if ( passphrase.length % 2 > 0 )
      throw new IllegalArgumentException("length out of range");
   
   buffer = Util.blockedBuffer( passphrase, BLOCKSIZE*2, 0 );
   cipher = Global.getStandardCipher();
   sbuf = cipher.encrypt( buffer );
   Util.destroyBytes( buffer );
   length = passphrase.length / 2;
}
 */

/** Constructor from an array containing a sequence of bytes, representing 
 *  characters as seen through the specified encoding.
 * 
 * @param buffer an array of byte containing the initial value for this PP as
 *        an encoded character sequence. 
 * @param enc the charset to which the content of the buffer is encoded; 
 *        <b>null</b> for VM default charset
 * @throws  IllegalCharsetNameException if the given charset name is illegal
 * @throws  UnsupportedCharsetException if no support for the named charset is 
 *          available in this instance of the Java virtual machine
 */
public PwsPassphrase ( byte[] buffer, String enc )
{
   cipher = Global.getStandardCipher();
   setBytes( buffer, enc );
}

/** Sets the content of this passphrase from a byte array which is encoded along 
 *  the specified character set.
 *  
 * @param buffer array of byte containing an encoded character sequence 
 * @param enc the encoding charset for the content of the buffer;
 *        <b>null</b> for VM default charset
 *  
 * @throws  IllegalCharsetNameException if the given charset name is illegal
 * @throws  UnsupportedCharsetException if no support for the named charset is 
 *          available in this instance of the Java virtual machine
 */
public void setBytes ( byte[] buffer, String enc )
{
   CharBuffer cbuf;

   if ( enc == null )
      enc = Global.getDefaultCharset();
   cbuf = Charset.forName( enc ).decode( ByteBuffer.wrap( buffer ) );
   setValue( cbuf.array(), cbuf.position(), cbuf.remaining() );
   Util.destroyChars( cbuf.array() );
}

/** A deep clone of this passphrase object.
 */
public Object clone ()
{
   PwsPassphrase pp;
   try { 
      pp = (PwsPassphrase) super.clone();
      pp.sbuf = (byte[])sbuf.clone();
      return pp;
      }
   catch ( CloneNotSupportedException e )
   { 
      return null; 
   }
}

/** Destroyes the contents of this PP in a secure way.
 */
public void clear ()
{
   length = 0;
   sbuf = NULLVALUE;
}

/** Sets the value of this instance from another passphrase object.
 * 
 * @param value <code>PwsPassphrase</code> to be copied or <b>null</b>
 * @since 2-1-0
 */
public void setValue ( PwsPassphrase value )
{
   char[] buf;
   
   if ( value == null )
      clear();
   else
   {
      buf = value.getValue();
      setValue( buf );
      Util.destroyChars( buf );
   }
}

/** Sets the value of this instance from the cleartext parameter string.
 * 
 * @param value the new value for this passphrase or <b>null</b>
 */
public void setValue ( String value )
{
   char[] buf;
   
   if ( value == null )
      clear();
   else
   {
      buf = value.toCharArray();
      setValue( buf );
      Util.destroyChars( buf );
   }
}

/** Sets the value of this instance from the cleartext parameter char array.
 * 
 * @param value the new value for this PP or <b>null</b>
 */
public void setValue ( char[] value )
{
   if ( value == null )
      clear();
   else
      setValue( value, 0, value.length );
}

/** Sets the value of this instance from the cleartext parameter char array, 
 *  comprising <code>length</code> characters starting from index <code>start</code>.
 * 
 * @param value defining source for the new value of this instance or <b>null</b>
 * @param start starting offset in value
 * @param length the activated length of <code>value</code>  
 */
public void setValue ( char[] value, int start, int length )
{
   int blocks, i;
   char ch;
   byte[] buf;
   
   if ( value == null )
   {
      clear();
      return;
   }
   
   if ( length < 0 | start < 0 | start+length > value.length )
      throw new IllegalArgumentException("length out of range");

   // make a cipher conforming block
   blocks = length / BLOCKSIZE;
   if ( length % BLOCKSIZE > 0 )
      blocks++;
   buf = new byte[ blocks * BLOCKSIZE * 2 ];
   this.length = length;

   // transfer content to cipher buffer
   for ( i = 0; i < length; i++ )
   {
      // store in little-endian manner (C-compatible)
      ch = value[ start + i ];
      buf[ i*2 ] = (byte)ch;
      buf[ i*2+1 ] = (byte)(ch >>> 8);
   }

   // encrypt content
   sbuf = cipher.encrypt( buf );
   Util.destroyBytes( buf );
}  // setValue

/** Sets the value of this PP from an encrypted byte buffer and a given cipher.
 * It is assumed that the contents of parameter <code>buffer</code> are encrypted
 * with the specified cipher <code>cph</code>. It is further assumed 
 * that the (decrypted) contents of the array are to be interpreted as as sequence
 * of Unicode-16 characters c, each represented by an integer <code>(short)c</code>, 
 * stored in Little-Endian (!) representation. 
 * 
 * @param buffer the new value for this passphrase as encrypted data block; 
 *        the length of the array must be a multiple of BLOCKSIZE * 2
 * @param length the active length of the intended character sequence; 
 *        0..buffer.length/2
 * @param cph PwsCipher that can be used to cryptograph this password's
 *        value  
 */
protected void setEncrypted ( byte[] buffer, int length, PwsCipher cph )
{
   if ( buffer.length % (BLOCKSIZE *2) > 0 )
      throw new IllegalArgumentException("illegal buffer block length");
      
   if ( cph == null )
      throw new NullPointerException("cipher");
      
   if ( length < 0 | length > buffer.length/2 )
      throw new IllegalArgumentException("length out of range");

   sbuf = (byte[]) buffer.clone();
   this.length = length;
   this.cipher = cph;
}  // setValue



/** Returns the decrypted value of this passphrase as an array of bytes.
 *  The conversion of the internal chars representaion to the sequence of
 *  bytes follows the encoding charset as specified by the parameter.
 * 
 * @param enc charset encoding standard; <b>null</b> for VM default charset  
 * @return array of bytes containing the encoded sequence of characters 
 *         forming this passphrase
 * 
 * @throws  IllegalCharsetNameException
 *          if the given charset name is illegal
 * @throws  UnsupportedCharsetException
 *          if no support for the named charset is available
 *          in this instance of the Java virtual machine
 */
public byte[] getBytes ( String enc )
{
   ByteBuffer bbuf;
   byte[] buffer;
   char cha[];

   cha = getValue();
   if ( enc == null )
      enc = Global.getDefaultCharset();
   bbuf = Charset.forName( enc ).encode( CharBuffer.wrap( cha ) );
   buffer = new byte[ bbuf.remaining() ];
   bbuf.get( buffer );
   
   // clean up the decrypted buffers
   Util.destroyChars( cha );
   Util.destroyBytes( bbuf.array() );
   
   return buffer;
}

/** Returns the decrypted value of this passphrase as an array of char. 
 *  If this value is void, an array of length 0 is returned.
 * 
 * @return array of char of the active length of he stored value, 
 *                 i.e. identical with <code>getLength()</code>
 */
public char[] getValue ()
{
   byte[] buffer;
   char c[];
   int i, ch;

   buffer = getValueBuffer();
   c = new char[ length ];

   // store into output char array
   for ( i = 0; i < length; i++ )
   {
      ch = (((int)buffer[ i*2 ] & 0xff) | (((int)buffer[ i*2+1 ] & 0xff) << 8));
      c[ i ] = (char)ch;
   }
   
   // clean up the decrypted buffer
   Util.destroyBytes( buffer );
   
   return c;
}  // getValue

/** Returns the value of this passphrase as a decrypted version of the 
 *  internal stored buffer. The content reflects only the active length of 
 *  passphrase (so the resulting length should be <code>getLength() * 2</code>).
 */
protected byte[] getValueBuffer ()
{
   byte[] buffer, result;

   buffer = cipher.decrypt( sbuf );
   result = new byte[ length*2 ];
   System.arraycopy( buffer, 0, result, 0, length*2 );
   Util.destroyBytes( buffer );
   return result;
}

/** Returns the encrypted data block of this passphrase as an array of bytes,
 *  encrypted along the cipher as specified by the parameter <code>PwsCipher</code>
 *  or by the internal cipher.
 *  The resulting array object is always separate from the internal value.
 * 
 * @param cph PwsCipher along which the return block will be encrypted; this
 *        may differ from the cipher used for storing this value. If <b>null</b>
 *        the internal cipher is used instead. 
 * @return encrypted array of bytes; length is a multiple of BLOCKSIZE * 2
 */
public byte[] getEncryptedBlock ( PwsCipher cph )
{
   byte[] buffer, buf2;

   buffer = (byte[]) sbuf.clone();
   
   if ( cph != null && !cph.equals( cipher ) )
   {
      buf2 = cipher.decrypt( buffer );
      buffer = cph.encrypt( buf2 );
      Util.destroyBytes( buf2 );
   }
   return buffer;
}

/** The length of the stored value in number of characters. */
public int getLength ()
{
   return length;
}

/** Returns the decrypted value of this passphrase as a <code>StringBuffer</code>.
 */
public StringBuffer getStringBuffer ()
{
   StringBuffer sb = new StringBuffer();
   char[] value = getValue();
   sb.append( value );

   // clean up the decrypted buffer
   Util.destroyChars( value );
   return  sb;
}

/** Returns the decrypted value of this passphrase as a <code>String</code>.
 *  If this value is void, an empty string is returned.
 *  <p>!!WARNING!! this undestoyable uncovered password value constitutes a
 *  security threat! It might not be ultimately avoidable though in certain 
 *  environments, but it should be used as sparing as possible.
 */
public String getString ()
{
   char[] value = getValue();
   String s = new String( value );

   // clean up the decrypted buffer
   Util.destroyChars( value );
   return s; 
}

/** Whether this object does not store a value (equivalent to 
 *  <code>getLength()==0</code>). */
public boolean isEmpty ()
{
   return length == 0;
}

/** Whether the parameter passphrase object equals this instance.
 *  Two <code>PwsPassphrase</code> objects are equal if and only if their 
 *  cleartext values are equal.
 * 
 *  @param obj instance of  <code>PwsPassphrase</code>
 *  @return <b>true</b> if and only if <code>obj</code> is not <b>null</b>,
 *          of type <code>PwsPassphrase</code> and its cleartext value is 
 *          identical with the corresponding value of this instance
 *  @throws ClassCastException if <code>obj</code> is not of same type     
 */
public boolean equals ( Object obj )
{
   byte[] b1, b2;
   boolean result;
   
   if ( obj == null )
      return false;
   
   b1 = ((PwsPassphrase) obj).getValueBuffer();
   b2 = this.getValueBuffer();
   result = Util.equalArrays( b1, b2 );
   Util.destroyBytes( b1 );
   Util.destroyBytes( b2 );
   return result;
}

/** 
 * Returns a hashcode value coherent with <code>equals()</code> for this
 * passphrase, based on its cleartext value. 
 */
public int hashCode ()
{
//   byte[] buffer;
   int result;
   
//   buffer = getValueBuffer();
   result = Util.arrayHashcode( sbuf );
//   Util.destroyBytes( buffer );
   return result;
}

/** Returns a textual representation of the <u>encrypted</u> stored value. */
public String toString ()
{
   return Util.bytesToHex( sbuf, 0, length*2 );
}
}
