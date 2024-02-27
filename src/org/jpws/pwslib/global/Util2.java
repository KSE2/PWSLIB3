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

import java.util.Iterator;
import java.util.SortedSet;
import java.util.TreeSet;

import kse.utilclass2.misc.CryptoRandom;


/**
 * Collection of useful routines for various purposes.
 * Includes a ready-to-use instance of a cryptographical 
 * random generator (<code>CrytoRandom</code>). 
 */
public class Util2 {
	
   /** Cryptological random generator.  */
   private static CryptoRandom cryptoRand = new CryptoRandom();
   

/**
 * Returns a cryptological random generator.
 * @return <code>CryptoRandom</code>
 * @since 2-1-0
 */   
public static CryptoRandom getCryptoRand () {
   return cryptoRand;
}

/**
 * Sets the cryptological random generator. 
 * @param cr <code>CryptoRandom</code>
 */
public static void setCryptoRandom ( CryptoRandom cr ) {
   if ( cr != null ) {
      cryptoRand = cr;
   }
}
   
/**
 * Converts an array from the native big-endian order to the little-endian 
 * order used by PasswordSafe. The array is transformed in-place.
 * The data is assumed to consist of a series of 32-bit integer values.
 * 
 * @param src the array to be byte-swapped.
 * @throws IllegalArgumentException if the array length is zero or not a 
 *         multiple of four bytes.
 */
public static void bytesToLittleEndian( byte [] src ) {
	if ( src.length == 0 | src.length % 4 != 0 )
		throw new IllegalArgumentException( "illegal buffer length" );

	for ( int i = 0; i < src.length; i += 4 ) {	
		byte temp		= src[i];
		src[i]	= src[i+3];
		src[i+3]	= temp;

		temp		= src[i+1];
		src[i+1]	= src[i+2];
		src[i+2]	= temp;
	}
} 

/**
 * Returns a string which is a copy of the parameter string 
 * where all ISO-controll characters are replaced by '%' characters.
 * 
 * @param s input string
 * @return mutated (printable) string version
 */
public static String printableString ( String s ) {
   int len = s.length();
   StringBuffer sbuf = new StringBuffer( len );
   for ( int i = 0; i < len; i++ ) {
	  char c;
      if ( Character.isISOControl( c = s.charAt( i ) ) ) { 
         c = '%';
      }
      sbuf.append( c );
   }
   return sbuf.toString();   
}

/** Makes a scrambles of the user record (buffer) over the specified length only.
 *  This works resembling to a mirror and can both en-scatter and de-scatter a set 
 *  of data, depending on the parameter switch <code>enscatter</code>.
 *  <p>(Note that this algorithm is not bound onto a cyclic block length, while 
 *  the cipher is.)
 *  
 *  @param buffer byte[]
 *  @param start int offset in buffer
 *  @param length int data length
 *  @param enscatter boolean switch of the transformation direction. 
 *         <b>true</b> = enscatter, <b>false</b> = descatter
 */
public static void scatter ( byte[] buffer, int start, int length, boolean enscatter ) {
   int i,j,k,len, plo, phi, shift, loops, mod;
   byte x;

   // this scatters a series of blocks of 16 bytes length (analogic to encryption)
   // the last block may be of any lower size
   
   shift = enscatter ? 13 : -13;
   loops = length / 16;
   mod = length % 16;
   if ( mod > 0 )
      loops++;
   k = 15;
   len = 4;

   for ( j = 0; j < loops; j++ ) {
      if ( j == loops-1 && mod > 0 ) {
         k = mod-1;
         len = mod/4;
      }
      for ( i=0; i<len; i++ ) {
         plo = i * 2;
         phi = k - plo;
         x = buffer[ start+plo ];
         buffer[ start+plo ] = (byte)(buffer[ start+phi ] + shift);
         buffer[ start+phi ] = (byte)(x + shift);
      }
      start += 16;
   }
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
public static char[] excludeCharset ( char[] symbols, char[] exc ) {
   StringBuffer buffer = new StringBuffer();
   char c, result[] = null;
   int i, j;
   boolean ok;
   
   if ( symbols != null & exc != null ) {
      for ( i = 0; i < symbols.length; i++ ) {
         c = symbols[ i ];
         ok = true;
         for ( j = 0; j < exc.length & ok; j++  ) {
            if ( c == exc[ j ] ) ok = false;
         }
         if ( ok ) {
            buffer.append( c );
         }
      }
      result = buffer.toString().toCharArray(); 
   }
   return result;
}

/** Returns an array of characters with 2 features: a) elements are 
 * naturally sorted, b) each element appears only once.
 * 
 * @param ownSymbols char[] any sequence of characters
 * @return char[] sorted set of characters
 */
public static char[] clearedSymbolSet ( char[] ownSymbols ) {
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
         result[ i++ ] = it.next().charValue();
      }
      return result;
   }
   return null;
}


// **********  BOUNDARY  ************

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

///**
// * Returns the content of the parameter byte array <code>b</code> in a second 
// * byte array <code>r</code> whose length is at least as large as <code>b</code> 
// * but an integer multiple of <code>blocksize</code>. The length difference of
// * r and b is less than <code>blocksize</code> except when <code>minBlocks</code> 
// * arranges a greater length. Additional content is assigned zero values.  
// *  
// * @param b source byte array to reflect
// * @param blocksize "root" value of the resulting array's length
// * @param minBlocks the minimum number of blocks allocated for the resulting array 
// * @return a normalised byte array with the content of <code>b</code> 
// */
//public static byte[] blockedBuffer ( byte[] b, int blocksize, int minBlocks )
//{
//   byte[] buffer;
//   int blocks;
//   
//   blocks = b.length / blocksize;
//   if ( b.length % blocksize > 0 )
//      blocks++;
//   blocks = Math.max( minBlocks, blocks );
//   buffer = new byte[ blocks * blocksize ];
//   System.arraycopy( b, 0, buffer, 0, b.length );
//
//   return buffer;
//}





}
