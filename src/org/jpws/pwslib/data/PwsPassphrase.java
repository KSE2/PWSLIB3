/*
 *  File: PwsPassphrase.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 07.08.2004
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

package org.jpws.pwslib.data;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.IllegalCharsetNameException;
import java.nio.charset.UnsupportedCharsetException;

import org.jpws.pwslib.crypto.PwsCipher;
import org.jpws.pwslib.crypto.SHA1;
import org.jpws.pwslib.global.Global;
import org.jpws.pwslib.global.Util;

/**
 * PwsPassphrase represents a sequence of characters which is especially
 * protected against uncoverage through attacking tools analysing the JVM memory.
 * By the design of this class, there is always a cryptographic cipher defined
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
   private static final byte[] NULLVALUE = new byte[0];
   
   /**  The cipher used to encrypt the passphrase content (sbuf is
    *   always encrypted)
    */
   private PwsCipher cipher;
   
   /** Passphrase buffer; meant to store chars serialised by 2 bytes each.
    *  Must size as an int multiple of BLOCKSIZE * 2 
    */
   private byte[] sbuf;
   
   /** Length in number of chars; ranges 0..sbuf.length/2 
    */
   private int length;
   
   /** The text blocksize required for operations with encrypted data blocks.
    *  (i.e. half of the cipher blocksize)
    */
   private int blocksize;

   /** Hash-value representing the cleartext value of this instance. 
    *  Used by equals() and hashcode().
    */
   private long hashval;
   
   
/** Constructor for an empty passphrase and the default cipher.
 */
public PwsPassphrase ()
{
   cipher = Global.getStandardCipher();
   blocksize = cipher.getBlockSize() / 2;
   sbuf = NULLVALUE;
}

/** Constructor for an empty passphrase with a special cipher. 
 * 
 * @param ci <code>PwsCipher</code> a fully initialised ECB mode cipher  
 */
public PwsPassphrase ( PwsCipher ci )
{
   cipher = ci;
   blocksize = cipher.getBlockSize() / 2;
   sbuf = NULLVALUE;
}

/** Constructor with char array as initial value.
 * 
 * @param content char[] forming the initial value for this passphrase; 
 *        may be null
 */
public PwsPassphrase ( char[] content )
{
   cipher = Global.getStandardCipher();
   blocksize = cipher.getBlockSize() / 2;
   setValue( content );
}

/** Constructor with string as initial value.
 * 
 * @param content String text string forming the initial value of this 
 *                   passphrase; may be null
 */
public PwsPassphrase ( String content )
{
   cipher = Global.getStandardCipher();
   blocksize = cipher.getBlockSize() / 2;
   setValue( content );
}

/** Constructor from a byte array containing binary serialisation 
 * of a character sequence with the given encoding.
 * 
 * @param buffer an array of byte containing the initial value for this PP as
 *        an encoded character sequence. 
 * @param enc the charset to which the content of the buffer is encoded; 
 *        <b>null</b> for VM default charset
 * @throws  IllegalCharsetNameException if the given charset name is illegal
 * @throws  UnsupportedCharsetException if no support for the named charset is 
 *          available in this instance of the Java virtual machine
 */
public PwsPassphrase ( byte[] buffer, String enc ) {
	this( buffer, 0, buffer.length, enc );
}

/** Constructor from a byte array section containing binary serialisation 
 * of a character sequence with the given encoding.
 * 
 * @param buffer an array of byte containing the initial value for this PP as
 *        an encoded character sequence
 * @param offset int buffer start offset
 * @param length int data length in buffer 
 * @param enc the charset to which the content of the buffer is encoded; 
 *        <b>null</b> for VM default charset
 * @throws  IllegalCharsetNameException if the given charset name is illegal
 * @throws  UnsupportedCharsetException if no support for the named charset is 
 *          available in this instance of the Java virtual machine
 */
public PwsPassphrase ( byte[] buffer, int offset, int length, String enc ) {
   cipher = Global.getStandardCipher();
   blocksize = cipher.getBlockSize() / 2;
   setBytes( buffer, offset, length, enc );
}

/** Sets the content of this passphrase from a byte array which is encoded with 
 *  the specified character set.
 *  
 * @param buffer array of byte containing an encoded character sequence 
 * @param enc String name of charset for the content of the buffer;
 *        <b>null</b> for VM default
 *  
 * @throws  IllegalCharsetNameException if the given charset name is illegal
 * @throws  UnsupportedCharsetException if no support for the named charset is 
 *          available
 */
public void setBytes ( byte[] buffer, String enc ) {
	setBytes(buffer, 0, buffer.length, enc);
}

/** Sets the content of this passphrase from a byte array section which is 
 * encoded with the specified character set.
 *  
 * @param buffer array of byte containing an encoded character sequence 
 * @param offset int buffer start offset
 * @param length int data length in buffer 
 * @param enc String name of charset for the content of the buffer;
 *        <b>null</b> for VM default
 *  
 * @throws  IllegalCharsetNameException if the given charset name is illegal
 * @throws  UnsupportedCharsetException if no support for the named charset is 
 *          available
 */
public void setBytes ( byte[] buffer, int offset, int length, String enc ) {
   if ( enc == null ) {
      enc = Global.getDefaultCharset();
   }
   CharBuffer cbuf = Charset.forName( enc ).decode( ByteBuffer.wrap( buffer, offset, length ) );
   setValue( cbuf.array(), cbuf.position(), cbuf.remaining() );
   Util.destroyChars( cbuf.array() );
}

/** Returns a deep clone of this passphrase object.
 * 
 * @return Object 
 */
public Object clone ()
{
   try { 
	  PwsPassphrase pp = (PwsPassphrase) super.clone();
      pp.sbuf = (byte[])sbuf.clone();
      return pp;
   } catch ( CloneNotSupportedException e ) { 
      return null; 
   }
}

/** Destroys the contents of this PP in a secure way and sets length to zero.
 */
public void clear ()
{
   length = 0;
   sbuf = NULLVALUE;
   hashval = 0;
}

/** Sets the value of this instance from another passphrase object.
 * 
 * @param value <code>PwsPassphrase</code> to be copied or <b>null</b>
 */
public void setValue ( PwsPassphrase value )
{
   if ( value == null ) {
      clear();
   } else {
	  char[] buf = value.getValue();
      setValue( buf );
      Util.destroyChars( buf );
   }
}

/** Sets the value of this instance from the (cleartext) parameter string.
 * 
 * @param value the new value for this passphrase or <b>null</b> to clear
 */
public void setValue ( String value )
{
   if ( value == null ) {
      clear();
   } else {
	  char[] buf = value.toCharArray();
      setValue( buf );
      Util.destroyChars( buf );
   }
}

/** Sets the value of this instance from the (cleartext) parameter char array.
 * A copy of the parameter is used.
 * 
 * @param value array of char, the new value for this PP or <b>null</b>
 *              to clear
 */
public void setValue ( char[] value )
{
   if ( value == null ) {
      clear();
   } else {
      setValue( value, 0, value.length );
   }
}

/** Sets the value of this instance from the cleartext parameter char array, 
 *  comprising <code>length</code> characters starting from index <code>start</code>.
 *  A copy of the data section is used.
 * 
 * @param buffer char array, source data for the new value or <b>null</b> 
 *               to clear
 * @param start int starting offset in buffer
 * @param length int selected data length in buffer   
 * @throws IllegalArgumentException if section settings are invalid
 */
public void setValue ( char[] buffer, int start, int length )
{
   if ( buffer == null ) {
      clear();
      return;
   }
   
   if ( length < 0 | start < 0 | start+length > buffer.length )
      throw new IllegalArgumentException("length out of range");

   // make a cipher conforming block
   int blocks = length / blocksize;
   if ( length % blocksize > 0 ) {
      blocks++;
   }
   byte[] buf = new byte[ blocks * blocksize * 2 ];
   this.length = length;

   // transfer content to cipher buffer
   for ( int i = 0; i < length; i++ ) {
      // store in little-endian manner (C-compatible)
      char ch = buffer[ start + i ];
      buf[ i*2 ] = (byte)ch;
      buf[ i*2+1 ] = (byte)(ch >>> 8);
   }

   // create hash value
   SHA1 sha = new SHA1();
   sha.update(buf, 0, length*2);
   sha.finalize();
   hashval = Util.readLong( sha.getDigest(), 0 );
   
   // encrypt content
   sbuf = cipher.encrypt( buf );
   Util.destroyBytes( buf );
}  // setValue

///** Sets the value of this PP from an encrypted byte buffer and a given cipher.
// * It is assumed that the contents of parameter <code>buffer</code> are encrypted
// * with the specified cipher <code>cph</code>. It is further assumed 
// * that the (decrypted) contents of the array are to be interpreted as as sequence
// * of Unicode-16 characters c, each represented by an integer <code>(short)c</code>, 
// * stored in Little-Endian (!) representation.
// * <p>This passphrase takes over both the value and the encryption cipher; a
// * copy of the buffer is used.
// * 
// * @param buffer byte array, the new value for this passphrase as encrypted 
// *        data block; the length of the array must be a multiple of the 
// *        cipher's blocksize
// * @param length the active length of the intended character sequence; 
// *        0..buffer.length/2
// * @param cph PwsCipher that is used to encrypt this password's value  
// */
//protected void setEncrypted ( byte[] buffer, int length, PwsCipher cph )
//{
//   if ( buffer.length % cph.getBlockSize() > 0 )
//      throw new IllegalArgumentException("illegal buffer block length");
//      
//   if ( length < 0 | length > buffer.length/2 )
//      throw new IllegalArgumentException("length out of range");
//
//   sbuf = (byte[]) buffer.clone();
//   this.length = length;
//   this.cipher = cph;
//   this.blocksize = cipher.getBlockSize() / 2;
//}  // setValue
//


/** Returns the decrypted value of this passphrase as an array of bytes.
 *  The conversion of the internal character representation to the sequence of
 *  bytes follows the encoding charset as specified by the parameter.
 * 
 * @param enc String charset name for encoding; <b>null</b> for VM default  
 * @return array of bytes containing the encoded sequence of characters 
 *         forming this passphrase
 * @throws  IllegalCharsetNameException if the given charset name is illegal
 * @throws  UnsupportedCharsetException if no support for the given charset 
 *          is available
 */
public byte[] getBytes ( String enc )
{
   if ( enc == null ) {
      enc = Global.getDefaultCharset();
   }

   char[] cha = getValue();
   ByteBuffer bbuf = Charset.forName( enc ).encode( CharBuffer.wrap( cha ) );
   byte[] buffer = new byte[ bbuf.remaining() ];
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
   byte[] buffer = getValueBuffer();
   char[] ca = new char[ length ];

   // store into output char array
   for ( int i = 0; i < length; i++ ) {
      int ch = (((int)buffer[i*2] & 0xff) | (((int)buffer[i*2+1] & 0xff) << 8));
      ca[ i ] = (char)ch;
   }
   
   // clean up the decrypted buffer
   Util.destroyBytes( buffer );
   return ca;
}  // getValue

/** Returns the value of this passphrase as a decrypted version of the 
 *  internal stored buffer. The content reflects only the active length of 
 *  passphrase (so the resulting length should be <code>getLength() * 2</code>).
 *  
 *  @return array of bytes
 */
protected byte[] getValueBuffer ()
{
   byte[] result, buffer = cipher.decrypt( sbuf );
   int buflen = length*2;
   
   if ( buffer.length > buflen ) {
	   result = Util.arraycopy(buffer, buflen);
	   Util.destroyBytes( buffer );
   } else {
	   result = buffer;
   }
   return result;
}

/** Returns the encrypted data block of this passphrase as an array of bytes,
 *  encrypted by the cipher given with the parameter or by the internal cipher
 *  if the parameter is null.
 *  <p>The resulting array object is always separate from the internal value.
 * 
 * @param cph <code>PwsCipher</code> by which the returned block will be 
 *        encrypted; this may differ from the cipher used for storing this value.
 *        If <b>null</b> the internal cipher is used instead. 
 * @return encrypted array of bytes
 */
public byte[] getEncryptedBlock ( PwsCipher cph )
{
   byte[] buffer;
   
   if ( cph != null && !cph.equals( cipher ) ) {
	  buffer = sbuf;
	   
	   // correct buffer size if cipher lengths mismatch
	  int cbl = cph.getBlockSize();
	  if ( sbuf.length % cbl > 0 ) {
		  int newSize = (sbuf.length / cbl + 1) * cbl;
		  buffer = Util.arraycopy(sbuf, newSize);
	  }

	  // decrypt local + encrypt external cipher
      byte[] buf2 = cipher.decrypt( buffer );
      buffer = cph.encrypt( buf2 );
      Util.destroyBytes( buf2 );
      
   } else {
	   buffer = (byte[]) sbuf.clone();
   }
   return buffer;
}

/** The length of the stored value in number of characters.
 * 
 *  @return int length of text value
 */
public int getLength ()
{
   return length;
}

/** Returns the decrypted value of this passphrase as a <code>StringBuffer</code>.
 * 
 * @return <code>StringBuffer</code>
 */
public StringBuffer getStringBuffer ()
{
   StringBuffer sb = new StringBuffer();
   char[] value = getValue();
   sb.append( value );
   Util.destroyChars( value );
   return  sb;
}

/** Returns the decrypted value of this passphrase as a <code>String</code>.
 *  If this value is void, an empty string is returned.
 *  <p><b>!!WARNING!!</b> Returned undestoyable, uncovered password value 
 *  constitutes a security threat! It might not be ultimately avoidable though 
 *  in certain environments, but it should be used as sparingly as possible.
 *  
 *  @return String decrypted text value
 */
public String getString ()
{
   char[] value = getValue();
   String s = new String( value );

   // clean up the decrypted buffer
   Util.destroyChars( value );
   return s; 
}

/** Whether the value of this passphrase is empty.
 * 
 * @return boolean
 */
public boolean isEmpty ()
{
   return length == 0;
}

/** Returns the encryption cipher used by this passphrase.
 * 
 * @return <code>PwsCipher</code>
 */
protected PwsCipher getCipher () {
	return cipher;
}

/** Whether the parameter object equals this instance.
 *  Two <code>PwsPassphrase</code> objects are equal if and only if their 
 *  cleartext values are equal.
 * 
 *  @param obj instance of  <code>PwsPassphrase</code>
 *  @return <b>true</b> if and only if <code>obj</code> is not <b>null</b>,
 *          of type <code>PwsPassphrase</code> and its cleartext value is 
 *          identical with the corresponding value of this instance
 */
public boolean equals ( Object obj )
{
   if ( obj == null || !(obj instanceof PwsPassphrase)) return false;
   PwsPassphrase pass = (PwsPassphrase)obj;
   
   return hashval == pass.hashval;
   
//   byte[] b1 = pass.getValueBuffer();
//   byte[] b2 = this.getValueBuffer();
//   boolean result = Util.equalArrays( b1, b2 );
//   Util.destroyBytes( b1 );
//   Util.destroyBytes( b2 );
//   return result;
}

/** 
 * Returns a hashcode value coherent with <code>equals()</code> for this
 * passphrase, based on its cleartext value. 
 * 
 * @return int hashcode
 */
public int hashCode ()
{
	return (int)hashval;
	
//   byte[] buf = this.getValueBuffer();
//   int result = Util.arrayHashcode( buf );
//   Util.destroyBytes(buf);
//   return result;
}

/** Returns a hexadecimal text representation of the <u>encrypted</u> 
 *  stored value. For an empty value the empty string is returned.
 * 
 *  @return String
 */
public String toString ()
{
   return Util.bytesToHex( sbuf, 0, length*2 );
}
}
