/*
 *  File: TestC_PwsPassphrase.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 21.07.2005
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

import java.io.UnsupportedEncodingException;

import junit.framework.TestCase;

import org.jpws.pwslib.crypto.BlowfishCipher;
import org.jpws.pwslib.crypto.PwsCipher;
import org.jpws.pwslib.global.Util;

/**
 *  TestC_PwsPassphrase in org.jpws.pwslib.data
 */
public class TestC_PwsPassphrase extends TestCase
{
   
   public TestC_PwsPassphrase () 
   {
	   
   }
	
public void test_Construct_00 ()
{
   PwsPassphrase pp;
   String value;
   byte[] bas;
   int vlen;

   vlen = Util.nextRandByte();
   bas = Util.randomBytes(vlen);
   value = new String( bas, 0 );
   pp = new PwsPassphrase();
   pp.setValue( value );
   
   assertEquals( "construct 0-a, value equals", value, pp.getString() );
   assertEquals( "construct 0-b, value equals", value, 
         new String( pp.getValue() ) );
   assertTrue( "construct 0-c, value equals", Util.equalArrays( 
         bas, pp.getBytes("iso-8859-1")) );
   assertEquals( "construct 0-d, value equals", value, 
         pp.getStringBuffer().toString() );
   assertEquals( "construct 0, length", pp.getLength(), vlen );
   assertFalse( "construct 0, not empty", pp.isEmpty() );
   printPP( pp );
}

public void test_Construct_01 ()
{
   PwsPassphrase pp;
   String value;
   byte[] bas;
   int vlen;
   
   vlen = Util.nextRandByte();
   bas = Util.randomBytes(vlen);
   value = new String( bas, 0 );
   pp = new PwsPassphrase( value );
   
   assertEquals( "construct 1-a, value equals", value, pp.getString() );
   assertEquals( "construct 1-b, value equals", value, 
         new String( pp.getValue() ) );
   assertTrue( "construct 1-c, value equals", Util.equalArrays( 
         bas, pp.getBytes("iso-8859-1")) );
   assertEquals( "construct 0-d, value equals", value, 
         pp.getStringBuffer().toString() );
   assertEquals( "construct 1, length", pp.getLength(), vlen );
   assertFalse( "construct 1, not empty", pp.isEmpty() );
   printPP( pp );
}

private boolean equalArrays ( char[] a, char[] b )
{
   return new String( a ).equals( new String( b ) );
}

private void printPP ( PwsPassphrase pp )
{
   System.out.println( "Length=" + pp.getLength() + " : " + pp );
}

public void test_Construct_02 ()
{
   PwsPassphrase pp;
   String value;
   byte[] bas;
   char[] chars;
   int vlen;

   vlen = Util.nextRandByte();
   bas = Util.randomBytes(vlen);
   value = new String( bas, 0 );
   chars = value.toCharArray(); 
   pp = new PwsPassphrase( chars );
   
   assertTrue( "construct 2-a, value equals", equalArrays( 
         chars, pp.getString().toCharArray()) );
   assertTrue( "construct 2-b, value equals", equalArrays( 
         chars, pp.getValue() ));
   assertTrue( "construct 2-c, value equals", Util.equalArrays( 
         bas, pp.getBytes("iso-8859-1")) );
   assertEquals( "construct 2, length", pp.getLength(), vlen );
   assertFalse( "construct 2, not empty", pp.isEmpty() );
   printPP( pp );
}

public void test_Construct_03 ()
{
   PwsPassphrase pp;
   String value;
   byte[] bas;
   char[] chars;
   int vlen;

   vlen = Util.nextRandByte();
   bas = Util.randomBytes(vlen);
   
   try {
      value = new String( bas, "iso-8859-1" );
      chars = value.toCharArray();
      pp = new PwsPassphrase( bas, "iso-8859-1" );
   }
   catch ( UnsupportedEncodingException e )
   {
      e.printStackTrace();
      fail( "construct 3, unsupported encoding" );
      return;
   }
   
   assertEquals( "construct 3-a, value equals", value, pp.getString() );
   assertTrue( "construct 3-b, value equals", equalArrays( 
         chars, pp.getValue() ));
   assertTrue( "construct 3-c, value equals", Util.equalArrays( 
         bas, pp.getBytes("iso-8859-1")) );
   assertEquals( "construct 3, length", pp.getLength(), vlen );
   assertFalse( "construct 3, not empty", pp.isEmpty() );
   printPP( pp );
}

public void test_Construct_04 ()
{
   PwsPassphrase pp;
   PwsCipher cipher;
   String value;
   byte[] bas;
   int vlen;

   vlen = Util.nextRandByte();
   bas = Util.randomBytes(vlen);
   
   value = new String( bas, 0 );
   cipher = new BlowfishCipher();
   pp = new PwsPassphrase( cipher );
   pp.setValue( value );
   
   assertEquals( "construct 4-a, value equals", value, pp.getString() );
   assertEquals( "construct 4-b, value equals", value, 
         new String( pp.getValue() ) );
   assertTrue( "construct 4-c, value equals", Util.equalArrays( 
         bas, pp.getBytes("iso-8859-1")) );
   assertEquals( "construct 4-d, value equals", value, 
         pp.getStringBuffer().toString() );
   assertEquals( "construct 4, length", pp.getLength(), vlen );
   assertFalse( "construct 4, not empty", pp.isEmpty() );
   printPP( pp );
}

public void test_clear ()
{
   PwsPassphrase pp;
   PwsCipher cp;
   String value;
   byte[] bas;
   int vlen;

   vlen = Util.nextRandByte();
   bas = Util.randomBytes(vlen);
   value = new String( bas, 0 );
   pp = new PwsPassphrase( value );
   pp.clear();
   printPP( pp );

   assertTrue( "clear, results zero length", pp.getLength() == 0 );
   assertTrue( "clear, results empty string", pp.getString().equals("") );
   assertTrue( "clear, results empty char-arr", pp.getValue().length == 0 );
   assertTrue( "clear, results empty byte-arr", pp.getBytes(null).length == 0 );
   assertTrue( "clear, results empty enc-byte-arr 1", pp.getEncryptedBlock(null).length == 0 );
   cp = new BlowfishCipher();
   assertTrue( "clear, results empty enc-byte-arr 2", pp.getEncryptedBlock(cp).length == 0 );
   assertTrue( "clear, results empty stringbuffer", pp.getStringBuffer().length() == 0 );
   assertTrue( "clear, results empty value-buffer", pp.getValueBuffer().length == 0 );
}

public void test_clone ()
{
   PwsPassphrase pp1, pp2;
   String value;
   char[] v1, v2;
   byte[] b1, b2, bas;
   int vlen;

   // clone empty object
   pp1 = new PwsPassphrase();
   pp2 = (PwsPassphrase)pp1.clone();
   
   assertEquals( "clone objects equal", pp1, pp2 );
   v1 = pp1.getValue(); v2 = pp2.getValue();
   assertTrue( "clone values equal", equalArrays( v1, v2 ) );
   b1 = pp1.getEncryptedBlock(null); 
   b2 = pp2.getEncryptedBlock(null);
   assertTrue( "clone sbufs equal", Util.equalArrays( b1, b2 ) );
   assertEquals( "clone lengths equal", pp1.getLength(), pp2.getLength() );
   
   // clone filled object
   vlen = Util.nextRandByte();
   bas = Util.randomBytes(vlen);
   value = new String( bas, 0 );
   pp1 = new PwsPassphrase( value );
   pp2 = (PwsPassphrase)pp1.clone();
   
   assertEquals( "clone objects equal, 2", pp1, pp2 );
   v1 = pp1.getValue(); v2 = pp2.getValue();
   assertTrue( "clone values equal, 2", equalArrays( v1, v2 ) );
   b1 = pp1.getEncryptedBlock(null); 
   b2 = pp2.getEncryptedBlock(null);
   assertTrue( "clone sbufs equal, 2", Util.equalArrays( b1, b2 ) );
   assertEquals( "clone lengths equal, 2", pp1.getLength(), pp2.getLength() );

   // clone cleared object
   pp1.clear();
   pp2 = (PwsPassphrase)pp1.clone();
   
   assertEquals( "clone objects equal, 3", pp1, pp2 );
   v1 = pp1.getValue(); v2 = pp2.getValue();
   assertTrue( "clone values equal, 3", equalArrays( v1, v2 ) );
   b1 = pp1.getEncryptedBlock(null); 
   b2 = pp2.getEncryptedBlock(null);
   assertTrue( "clone sbufs equal, 3", Util.equalArrays( b1, b2 ) );
   assertEquals( "clone lengths equal, 3", pp1.getLength(), pp2.getLength() );
}

public void test_Construct_05 ()
{
   PwsPassphrase pp;
   String value;
   byte[] bas;
   char[] chars;
   int vlen;

   value = "Im Küstenthäler ÜrßÖÄÜffa brummt ein Bär!";
   vlen = value.length();
   try { bas = value.getBytes( "utf-8" ); }
   catch ( UnsupportedEncodingException e )
   { 
      e.printStackTrace();
      fail( "construct 5, unsupported encoding" );
      return;
   }
   
   chars = value.toCharArray();
   pp = new PwsPassphrase( bas, "utf-8" );
   
   assertEquals( "construct 5-a, value equals", value, pp.getString() );
   assertTrue( "construct 5-b, value equals", equalArrays( 
         chars, pp.getValue() ));
   assertTrue( "construct 5-c, value equals", Util.equalArrays( 
         bas, pp.getBytes("utf-8")) );
   assertEquals( "construct 5, length", pp.getLength(), vlen );
   assertFalse( "construct 5, not empty", pp.isEmpty() );
   printPP( pp );
}


}