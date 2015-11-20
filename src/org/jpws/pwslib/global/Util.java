/*
 *  File: Util.java
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

package org.jpws.pwslib.global;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.DecimalFormatSymbols;
import java.util.Iterator;
import java.util.Random;
import java.util.SortedSet;
import java.util.TreeSet;

import org.jpws.pwslib.crypto.CryptoRandom;
import org.jpws.pwslib.crypto.SHA256;
import org.jpws.pwslib.order.DefaultRecordWrapper;


/**
 * Collection of useful routines for various purposes.
 * Includes a ready-to-use instance of a cryptographical 
 * random generator (<code>CrytoRandom</code>). 
 */
public class Util
{
   /** Cryptological random generator.
    *  @since 0-3-0
    *  @since 2-1-0 made private (was public)
    */
   private static CryptoRandom cryptoRand = new CryptoRandom();
   
   private static Random rand = new Random();
   

/**
 * Returns a cryptological random generator.
 * @return <code>CryptoRandom</code>
 * @since 2-1-0
 */   
public static CryptoRandom getCryptoRand ()
{
   return cryptoRand;
}

/**
 * Sets the cryptological random generator. 
 * @param cr <code>CryptoRandom</code>
 * @since 2-1-0
 */
public static void setCryptoRandom ( CryptoRandom cr )
{
   if ( cr != null )
      cryptoRand = cr;
}
   
/**
 * Returns a random value within the range 0 .. 255.
 * (non-cryptographical random)
 * 
 * @return a value <code>0 .. 255</code>
 */
public static int nextRandByte ()
{
   return rand.nextInt( 256 );
}

/**
 * Returns a random value within the range 0 .. range-1.
 * (non-cryptographical random)
 * 
 * @param range
 * @return a value <code>0 .. range-1</code>
 */
public static int getRandom ( int range )
{
   return rand.nextInt( range );
}

/**
 * Allocates a byte array with a length of <code>length</code> and fills it with
 * random data (non-cryptographical random).
 * 
 * @param length the length of the array.
 * 
 * @return A byte array initialised with random data.
 */
public static byte[] randomBytes( int length )
{
   byte[] array = new byte [ length ];
   for ( int i = 0; i < length; i++ )
   {
      array[ i ] = (byte)nextRandByte();
   }
   return array;
}

/**
 * Converts a byte array to a hexadecimal string.  Conversion starts at byte 
 * <code>offset</code> and continues for <code>length</code> bytes.
 * 
 * @param b      the array to be converted.
 * @param offset the start offset within <code>b</code>.
 * @param length the number of bytes to convert.
 * @return A string representation of the byte array.
 * @throws IllegalArgumentException if offset and length are misplaced
 */
public static String bytesToHex( byte [] b, int offset, int length )
{
   StringBuffer   sb;
   String         result;
   int i, top;

   if ( b == null )
      return "void";
   
   top = offset + length;
   if ( length < 0 || top > b.length )
      throw new IllegalArgumentException();

   sb = new StringBuffer();
   for ( i = offset; i < top; i++ )
   {
      sb.append( byteToHex( b[i] ) );
   }
   result = sb.toString();
   return result;
}

/** Converts a textual hexadecimal integer representation into a corresponding
 *  byte value array. 
 * 
 * @param hex textual hex value
 * @return array of derived value bytes
 * @since 0-4-0        
 */
public static byte[] hexToBytes ( String hex )
{
   ByteArrayOutputStream out;
   int i, pos;
   
   if ( hex.length() % 2 != 0 )
      throw new IllegalArgumentException( "hex string must be even" );
   
   out = new ByteArrayOutputStream( hex.length() / 2 );
   pos = 0;
   while ( pos < hex.length() )
   {
      i = Integer.parseInt( hex.substring( pos, pos+2 ), 16 );
      out.write( i );
      pos += 2;
   }
   return out.toByteArray();
}  // hexToBytes

/**
 * Converts a byte array to a hexadecimal string.  
 * 
 * @param b      the array to be converted.
 * @return A string representation of the byte array.
 */
public static String bytesToHex( byte [] b )
{
   if ( b == null )
      return "void";
   return bytesToHex( b, 0, b.length );
}

/** Returns a two char hexadecimal String representation of a single byte.
 * 
 * @param v integer with a byte value (-128 .. 255); other values get truncated
 * @return an absolute hex value representation (unsigned) of the input
 */
public static String byteToHex ( int v )
{
   String hstr;
   hstr = Integer.toString( v & 0xff, 16 );
   
   return hstr.length() == 1 ? "0" + hstr : hstr;
}

/** Returns a 4 char hexadecimal String representation of a single short integer.
 * 
 * @param v integer with a short value; other values get truncated
 * @return an absolute hex value representation (unsigned) of the input
 * @since 2-0-0
 */
public static String shortToHex ( int v )
{
   String hstr;
   hstr = Integer.toString( v & 0xffff, 16 );
   
   return "0000".substring( hstr.length() ) + hstr;
}

/** Returns a 8 char hexadecimal String representation of a single integer (int).
 * 
 * @param v integer with a short value; other values get truncated
 * @return an absolute hex value representation (unsigned) of the input
 * @since 2-0-0
 */
public static String intToHex ( long v )
{
   String hstr;
   hstr = Long.toString( v & 0xffffffffL, 16 );
   
   return "00000000".substring( hstr.length() ) + hstr;
}

/**
 * Writes a 64-bit integer value to a byte array as 
 * 8 sequential bytes in a Little-Endian manner 
 * (least significant stored first).
 *  
 * @param v long, the value to be written
 * @param dest the destination byte array
 * @param offs the start offset in <code>dest</code>
 */
public static void writeLongLittle ( long v, byte[] dest, int offs )
{
   dest[ offs ]     = (byte)(  v );
   dest[ offs + 1 ] = (byte)(  (v >>>  8) );
   dest[ offs + 2 ] = (byte)(  (v >>> 16) );
   dest[ offs + 3 ] = (byte)(  (v >>> 24) );
   dest[ offs + 4 ] = (byte)(  (v >>> 32) );
   dest[ offs + 5 ] = (byte)(  (v >>> 40) );
   dest[ offs + 6 ] = (byte)(  (v >>> 48) );
   dest[ offs + 7 ] = (byte)(  (v >>> 56) );
}

/**
 * Writes a 32-bit integer value to a byte array as
 * 4 sequential bytes in a Little-Endian manner 
 * (least significant stored first).
 *  
 * @param v int, the value to be written
 * @param dest the destination byte array
 * @param offs the start offset in <code>dest</code>
 */
public static void writeIntLittle ( int v, byte[] dest, int offs )
{
   dest[ offs ]     = (byte)(  v );
   dest[ offs + 1 ] = (byte)(  (v >>>  8) );
   dest[ offs + 2 ] = (byte)(  (v >>> 16) );
   dest[ offs + 3 ] = (byte)(  (v >>> 24) );
}

/**
 * Writes a 32-bit integer value to a byte array as
 * 4 sequential bytes in a Big-Endian manner 
 * (most significant stored first).
 *  
 * @param v int, the value to be written
 * @param dest the destination byte array
 * @param offs the start offset in <code>dest</code>
 * @since 2-1-0
 */
public static void writeInt ( int v, byte[] dest, int offs )
{
   dest[ offs ]     = (byte)(  (v >>> 24) );
   dest[ offs + 1 ] = (byte)(  (v >>> 16) );
   dest[ offs + 2 ] = (byte)(  (v >>>  8) );
   dest[ offs + 3 ]     = (byte)(  v );
}

/**
 * Reads a long (signed) integer value from a byte array as
 * 8 sequential bytes in a Little-Endian manner 
 * (least significant stored first).
 *  
 * @param b the source byte array
 * @param offs the start offset in <code>dest</code>
 * @return long integer as read from the byte sequence
 */
public static long readLongLittle ( byte[] b, int offs )
{
   return
   ((long)b[ offs ] & 0xff) | 
   (((long)b[ offs + 1 ] & 0xff) <<  8) |
   (((long)b[ offs + 2 ] & 0xff) <<  16) |
   (((long)b[ offs + 3 ] & 0xff) <<  24) |
   (((long)b[ offs + 4 ] & 0xff) <<  32) |
   (((long)b[ offs + 5 ] & 0xff) <<  40) |
   (((long)b[ offs + 6 ] & 0xff) <<  48) |
   (((long)b[ offs + 7 ] & 0xff) <<  56);
}

/**
 * Reads a integer value from a byte array as 4 sequential bytes in a 
 * Little-Endian manner (least significant stored first).
 *  
 * @param b the source byte array
 * @param offs the start offset in <code>dest</code>
 * @return int integer as read from the byte sequence
 */
public static int readIntLittle ( byte[] b, int offs )
{
   return
   ((int)b[ offs ] & 0xff) | 
   (((int)b[ offs + 1 ] & 0xff) <<  8) |
   (((int)b[ offs + 2 ] & 0xff) <<  16) |
   (((int)b[ offs + 3 ] & 0xff) <<  24);
}

/**
 * Reads an unsigned 4-byte integer value from a byte array in a 
 * Little-Endian manner (least significant stored first). The
 * returned value is a long integer. 
 *  
 * @param b the source byte array
 * @param offs the start offset in <code>dest</code>
 * @return long unsigned 32-bit integer as read from the byte sequence
 * @since 2-0-0
 */
public static long readUIntLittle ( byte[] b, int offs )
{
   return (long)readIntLittle( b, offs ) & 0xFFFFFFFFL; 
}

/**
 * Writes a long integer value to a byte array as 8 sequential bytes in a 
 * Big-Endian manner (Java-standard).
 *  
 * @param v long, the value to be written
 * @param dest the destination byte array
 * @param offs the start offset in <code>dest</code>
 */
public static void writeLong ( long v, byte[] dest, int offs )
{
   dest[ offs ]     = (byte)( (v >>> 56) );
   dest[ offs + 1 ] = (byte)( (v >>> 48) );
   dest[ offs + 2 ] = (byte)( (v >>> 40) );
   dest[ offs + 3 ] = (byte)( (v >>> 32) );
   dest[ offs + 4 ] = (byte)( (v >>> 24) );
   dest[ offs + 5 ] = (byte)( (v >>> 16) );
   dest[ offs + 6 ] = (byte)( (v >>>  8) );
   dest[ offs + 7 ] = (byte)( (v >>>  0) );
}

/**
 * Reads a long integer value from a byte array as 8 sequential bytes in a 
 * Big-Endian manner (Java-standard).
 *  
 * @param b the source byte array
 * @param offs the start offset in <code>dest</code>
 * @return long integer as read from the byte sequence
 */
public static long readLong ( byte[] b, int offs )
{
   return
   (((long)b[ offs + 0 ] & 0xff) <<  56) |
   (((long)b[ offs + 1 ] & 0xff) <<  48) |
   (((long)b[ offs + 2 ] & 0xff) <<  40) |
   (((long)b[ offs + 3 ] & 0xff) <<  32) |
   (((long)b[ offs + 4 ] & 0xff) <<  24) |
   (((long)b[ offs + 5 ] & 0xff) <<  16) |
   (((long)b[ offs + 6 ] & 0xff) <<   8) |
   (((long)b[ offs + 7 ] & 0xff) <<   0);
}

/**
 * Transforms a char array into a byte array by sequentially writing characters.
 * Each char is stored in Little-Endian manner as unsigned short integer value 
 * in the range 0..65535.
 * @param carr the source char array
 * @return byte array, the transformed state of the parameter with double length
 *         of the parameter  
 */
public static byte[] getByteArray ( char[] carr )
{
   byte[] buff;
   char ch;
   int i;
   
   // transfer content to internal cipher block
   buff = new byte[ carr.length * 2 ];
   for ( i = 0; i < carr.length; i++ )
   {
      ch = carr[ i ];
      buff[ i*2 ] = (byte)ch;
      buff[ i*2+1 ] = (byte)(ch >>> 8);
   }
   return buff;
}

/**
 * Destroyes the contents of the parameter byte array by assigning zero to
 * all elements.
 * @param v byte array to be destroyed
 */
public static void destroyBytes ( byte[] v )
{
   if ( v != null )
   for ( int i = 0; i < v.length; i++ )
      v[i] = 0;
}

/**
 * Destroyes the contents of the parameter char array by assigning zero to
 * all elements.
 * @param v char array to be destroyed
 */
public static void destroyChars ( char[] v )
{
   for ( int i = 0; i < v.length; i++ )
      v[i] = '\u0000';
}

/** Whether two byte arrays have equal contents.
 * 
 * @param a first byte array to compare
 * @param b second byte array to compare
 * @return <b>true</b> if and only if a) a and b have the same length, and 
 *          b) for all indices i for 0 to length holds a[i] == b[i]
 */
public static boolean equalArrays ( byte[] a, byte[] b )
{
   if ( a.length != b.length )
      return false;
   
   for ( int i = 0; i < a.length; i++ )
      if ( a[i] != b[i] )
         return false;
   return true;
}

/** Whether two byte arrays have equal contents in a specified section.
 * 
 * @param a first byte array to compare
 * @param b second byte array to compare (sectional element)
 * @param offset offset in b where to start comparison
 * @return <b>true</b> if and only if 1) b has a minimum length of a.length + offset,
 *          and 2) content of a equals b[ offset..offset+a.length ]
 * @since 2-0-0
 */
public static boolean equalArrays ( byte[] a, byte[] b, int offset )
{
   if ( b.length < a.length + offset )
      return false;
   
   for ( int i = 0; i < a.length; i++ )
      if ( a[i] != b[i+offset] )
         return false;
   return true;
}

///**
// * Returns an array of clone copies of the set of <code>DefaultRecordWrapper</code>
// * objects represented by the parameter array. Order preserved.
// * 
// * @param recs
// * @return array of <code>DefaultRecordWrapper</code>
// * @since 2-1-0
// */
//public static DefaultRecordWrapper[] cloneRecordWrappers ( DefaultRecordWrapper[] recs )
//{
//   DefaultRecordWrapper[] copy;
//   int i;
//   
//   copy = new DefaultRecordWrapper[ recs.length ];
//   for ( i = 0; i < recs.length; i++ )
//      copy[ i ] = (DefaultRecordWrapper) recs[ i ].clone(); 
//   return copy;
//}

/**
 * Returns the content of the parameter byte array <code>b</code> in a second 
 * byte array <code>r</code> whose length is at least as large as <code>b</code> 
 * but an integer multiple of <code>blocksize</code>. The length difference of
 * r and b is less than <code>blocksize</code> except when <code>minBlocks</code> 
 * arranges a greater length. Additional content is assigned zero values.  
 *  
 * @param b source byte array to reflect
 * @param blocksize "root" value of the resulting array's length
 * @param minBlocks the minimum number of blocks allocated for the resulting array 
 * @return a normalised byte array with the content of <code>b</code> 
 */
public static byte[] blockedBuffer ( byte[] b, int blocksize, int minBlocks )
{
   byte[] buffer;
   int blocks;
   
   blocks = b.length / blocksize;
   if ( b.length % blocksize > 0 )
      blocks++;
   blocks = Math.max( minBlocks, blocks );
   buffer = new byte[ blocks * blocksize ];
   System.arraycopy( b, 0, buffer, 0, b.length );

   return buffer;
}

/** Returns a copy of the parameter byte array of the given length. 
 *  The result will be identical, a shortage or a prolongation of the parameter 
 *  value, depending on the length setting.
 * 
 * @param b data source
 * @param start offset in b
 * @param length length in b
 * @return array segment of b
 */
public static byte[] arraycopy ( byte[] b, int start, int length )
{
   byte[] copy;
   
   copy = new byte[ length ];
   System.arraycopy( b, start, copy, 0, Math.min( length, b.length-start ));
   return copy;
}

/** Returns a copy of the parameter byte array of the given length. 
 *  The result will be identical, a shortage or a prolongation of the parameter 
 *  value, depending on the length setting.
 * 
 * @param b data source
 * @param length length in b
 * @return array segment within b from start offset 0
 */
public static byte[] arraycopy ( byte[] b, int length )
{
   return arraycopy( b, 0, length );
}

/** Returns a copy of the parameter byte array of the same length. 
 * 
 * @param b data source
 * @return array copy
 * @since 2-1-0
 */
public static byte[] arraycopy ( byte[] b )
{
   return arraycopy( b, 0, b.length );
}

/** Whether the given object is an element of a given array.
 * 
 * @param o Object
 * @param arr array of Object
 * @return boolean <b>true</b> if and only if one of the elements of <code>arr</code>
 *         <code>equals()</code> parameter <code>o</code>
 */
public static boolean isArrayElement ( Object o, Object[] arr )
{
   for ( int i = 0; i < arr.length; i++ )
      if ( o.equals( arr[i] ) )
         return true;
   return false;
}

/**
 * Returns a hashcode based on the content of the parameter array (instead of 
 * its address).
 * 
 * @param b the byte array to investigate
 * @return a content oriented hashcode for <code>b</code>
 */
public static int arrayHashcode ( byte[] b )
{
   long lv = 0;
   int j = 0;
   for ( int i = 0 ; i < b.length; i++ )
   {
      lv += ((long)b[i] & 0xff) << j++;
      if ( j > 23 )
         j = 0;
   }
   return (int) lv;
}

/**
 * Transfers the contents of the input stream to the output stream
 * until the end of input stream is reached.
 * 
 * @param input
 * @param output
 * @param bufferSize
 * @throws java.io.IOException
 */
public static void transferData ( InputStream input, OutputStream output,
      int bufferSize  )
throws java.io.IOException
{
byte[] buffer = new byte[ bufferSize ];
int len;

Log.log( 10, "(Util) data transfer start" ); 
while ( (len = input.read( buffer )) > 0 )
   output.write( buffer, 0, len );
Log.log( 10, "(Util) data transfer end" ); 
}  // transferData

/**
 * Converts an array from the native big-endian order to the little-endian order
 * used by PasswordSafe.  The array is transformed in-place.
 * 
 * @param src the array to be byte-swapped.
 * 
 * @throws IllegalArgumentException if the array length is zero or not a multiple of four bytes.
 */
public static void bytesToLittleEndian( byte [] src )
{
	byte	temp;
   int i;

	if ( src.length == 0 | src.length % 4 != 0 )
		throw new IllegalArgumentException( "illegal buffer length" );

	for ( i = 0; i < src.length; i += 4 )
	{	
		temp		= src[i];
		src[i]	= src[i+3];
		src[i+3]	= temp;

		temp		= src[i+1];
		src[i+1]	= src[i+2];
		src[i+2]	= temp;
	}
}  // bytesToLittleEndian

/** Returns a SHA-256 fingerprint value of the parameter byte buffer.
 * 
 * @param buffer data to digest
 * @return SHA256 digest
 * @since 0-3-0
 * @since 2-1-0 extended to SHA-256 (was SHA-1)
 */
public static byte[] fingerPrint ( byte[] buffer )
{
   SHA256 sha;

   sha = new SHA256();
   sha.update( buffer );
   sha.finalize();
   return sha.digest();
}

/** Renders a string based on <code>text</code> where any occurence of
 *  <code>token</code> is replaced by <code>substitute</code>. Replace
 *  takes place iteratively until not further occurence exists.
 *  
 *  @return String the result of transformation; <b>null</b> if any of the
 *          parameters is <b>null</b>
 *  @since 0-4-0        
 */
public static String substituteText ( String text, String token, String substitute )
{
   int index;

   if ( text == null | token == null | substitute == null || 
         (index=text.indexOf( token )) < 0 )
       return text;

   while ( index > -1 )
   {
      text = text.substring( 0, index ) + substitute +
             text.substring( index+token.length() );
      index = text.indexOf( token );
   }
   return text;
}  // substituteText

/** Renders a string based on <code>text</code> where the first occurrence of
 *  <code>token</code> is replaced by <code>substitute</code>.
 *  <br>(Returns the original if any of the parameters is <b>null</b> or length or
 *  <tt>token</tt> is zero.)
 *  
 *  @return String the result of substitute; <b>null</b> if any of the
 *          parameters is <b>null</b>
 *  @since 0-4-0        
 */
public static String substituteTextS ( String text, String token, 
      String substitute )
{
   int index;

   if ( text == null | token == null | substitute == null || 
        token.length() == 0 || (index=text.indexOf( token )) < 0 )
      return text;

   if ( index > -1 )
   {
      text = text.substring( 0, index ) + substitute +
             text.substring( index+token.length() );
   }
   return text;
}  // substituteText

/**
 * Returns a byte array of same length as the input buffers where the
 * result has XORed each ordinal position in both arrays (a XOR b).
 *  
 * @param a input byte array (same length as b)
 * @param b input byte array (same length as a)
 * @return XOR-ed a and b
 * @throws IllegalArgumentException if a and b have differing length
 * @since 2-0-0
 */
public static final byte[] XOR_buffers ( byte[] a, byte[] b )
{
   byte[] res;
   int i, len;
   
   if ( a.length != b.length )
      throw new IllegalArgumentException( "buffer a,b length must be equal" );
   
   len = a.length;
   res = new byte[ len ];
   for ( i = 0; i < len; i++ ) 
      res[i] = (byte) (a[i] ^ b[i]);

   return res;
}

/**
 * Returns a string representation of the parameter long integer value
 * including decimal separation signs (after VM default locale).
 *  
 * @param value long integer
 * @return dotted text representation
 * @since 2-0-0
 */
public static String dottedNumber ( long value )
  {
  String hstr = String.valueOf( value );
  String out= "";
  char sep = (new DecimalFormatSymbols()).getGroupingSeparator();
  int len= hstr.length();
  while( len > 3 )
     {
     out= sep + hstr.substring( len-3, len ) + out;
     hstr= hstr.substring( 0, len-3 );
     len= hstr.length();
     }
  return hstr + out;
  } // dottedNumber

/** Copies the content of an input stream into an output stream until
 * the end of the input stream is reached.
 * 
 * @param in InputStream
 * @param out OutputStream
 * @throws IOException
 * @since 2-1-0
 */
public static void copyStream ( InputStream in, OutputStream out ) throws IOException
{
   byte[] buffer = new byte[8*2048];
   int len;
   
   while ((len = in.read(buffer)) != -1)
      out.write(buffer, 0, len);
}

/**
 * Returns a string which is a copy of the parameter string 
 * where all ISO-controll characters are replaced by '%' characters.
 * 
 * @param s input string
 * @return mutated (printable) string version
 * @since 2-1-0
 */
public static String printableString ( String s )
{
   StringBuffer sbuf;
   int i, len;
   char c;
   
   len = s.length();
   sbuf = new StringBuffer( len );
   for ( i = 0; i < len; i++ )
   {
      if ( Character.isISOControl( c = s.charAt( i ) ) ) 
         c = '%';
      sbuf.append( c );
   }
   return sbuf.toString();   
}

/**
 * Returns a URL object constructed from the given file path. This method 
 * first attempts to interpret <code>filepath</code> as a regular URL 
 * nominator. If this fails it attempts to see <code>filepath</code> as
 * a local file path nominator and returns a "file:" protocol URL. Local
 * filepaths get canonized.
 *    
 * @param filepath
 * @return URL for parameter file path
 * @throws MalformedURLException if <code>filepath</code> is malformed
 * @throws IOException if some IO error occurs 
 */
public static URL makeFileURL ( String filepath ) 
      throws IOException
{
   URL url;
   File file;
   String path;
   
   // first attempt: if filepath is a qualified url nominator
   try { url = new URL( filepath ); }
   catch ( MalformedURLException e )
   {
      // second attempt: generate URL from assumed local filepath
      file = new File( filepath );
      try { file = file.getCanonicalFile(); }
      catch ( Exception e1 )
      {}
      path = file.getAbsolutePath();
      if ( !path.startsWith("/") )
         path = "/" + path;
      url = new URL( "file:" + path );
   }
   return url; 
}

/** Whether two character arrays have equal contents.
 * 
 * @param a first char array to compare
 * @param b second char array to compare
 * @return <b>true</b> if and only if a) a and b have the same length, and 
 *          b) for all indices i for 0 to length holds a[i] == b[i]
 */
public static boolean equalArrays ( char[] a, char[] b )
{
   if ( a.length != b.length )
      return false;
   
   for ( int i = 0; i < a.length; i++ )
      if ( a[i] != b[i] )
         return false;
   return true;
}

/** Returns an array of characters with 2 features: a) elements are 
 * naturally sorted, b) each element appears only once.
 * 
 * @param ownSymbols char[] any sequence of characters
 * @return char[] sorted set of characters
 */
public static char[] clearedSymbolSet ( char[] ownSymbols )
{
   SortedSet<Character> set = new TreeSet<Character>();
   char[] result;
   int i = 0;
   
   if ( ownSymbols != null ) {
      for ( i = 0; i < ownSymbols.length; i++ ) {
         set.add( new Character( ownSymbols[ i ] ) );
      }
      
      i = 0;
      result = new char[ set.size() ]; 
      for ( Iterator<Character> it = set.iterator(); it.hasNext(); ) {
         result[ i++ ] = ((Character)it.next()).charValue();
      }
      return result;
   }
   return null;
}

/** Character set subtraction. Returns an array of characters with 
 * 2 features: a) elements are also element in "symbols", 
 * b) elements are not elements in "exc". The sorting of elements 
 * is the same as in "symbols".
 * 
 * @param symbols char[] any sequence of characters
 * @param exc char[] characters to be excluded from symbols
 * @return char[] character set consisting of "symbols" subtracted by all occurrences
 *         of characters in "exc"
 */
public static char[] excludeCharset ( char[] symbols, char[] exc )
{
   StringBuffer buffer = new StringBuffer();
   char c, result[] = null;
   int i, j;
   boolean ok;
   
   if ( symbols != null & exc != null )
   {
      for ( i = 0; i < symbols.length; i++ )
      {
         c = symbols[ i ];
         ok = true;
         for ( j = 0; j < exc.length & ok; j++  )
            if ( c == exc[ j ] )
               ok = false;
         if ( ok )
            buffer.append( c );
      }
      result = buffer.toString().toCharArray(); 
   }
   return result;
}
}
