/*
 *  File: TestC_Ciphers.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 07.07.2006
 * 
 *  Copyright (c) 2006-2015 by Wolfgang Keller, Munich, Germany
 * 
 This program is copyright protected to the author(s) stated above. However, 
 you can use, redistribute and/or modify it for free under the terms of the 
 2-clause BSD-like license given in the document section of this project.  

 This program is distributed in the hope that it will be useful, but WITHOUT
 ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 FOR A PARTICULAR PURPOSE. See the license for more details.
*/

package org.jpws.pwslib.crypto;

import org.jpws.pwslib.global.Util2;

import junit.framework.TestCase;
import kse.utilclass.misc.Util;

public class TestC_Ciphers extends TestCase {

public void test_twofish () {
   assertTrue( "TWOFISH Selftest passed", Twofish.self_test() );
   
   assertTrue( "TWOFISH vector-test passed", twofish_ecb() );
   
}


public void test_scatter () {
   assertTrue( "SCATTER Selftest passed", ScatterCipher.self_test() );
   
}


private byte[][][] blow_evdata = {
      { {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, {0x4E,(byte)0xF9,(byte)0x97,0x45,0x61,(byte)0x98,(byte)0xDD,0x78} },                                 
      { {(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF}, {(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF}, {0x51,(byte)0x86,0x6F,(byte)0xD5,(byte)0xB8,0x5E,(byte)0xCB,(byte)0x8A} },
      { {(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF}, {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, {(byte)0xF2,0x1E,(byte)0x9A,0x77,(byte)0xB7,0x1C,0x49,(byte)0xBC} },
      { {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, {(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF}, {0x01,0x49,0x33,(byte)0xE0,(byte)0xCD,(byte)0xAF,(byte)0xF6,(byte)0xE4} },
                            };

public void test_blowfish_ecb () {
   PwsCipher cipher;
   byte[] buf;
   byte[][] vector;
   int i, x;
   
   for ( i = 0; i < blow_evdata.length; i++ ) {
      vector = blow_evdata[i];
      cipher = new BlowfishCipher( vector[0] );
      buf = vector[1];
      Util2.bytesToLittleEndian( buf );
      buf = cipher.encrypt( vector[1] );
      Util2.bytesToLittleEndian( buf );
      
      assertTrue( "ECB Vector Item No. " +i, Util.equalArrays( buf, vector[2] ));
      System.out.println( i + " : " +  Util.bytesToHex( vector[0] ) + ", " + 
            Util.bytesToHex( vector[1] ) +  " -> " + Util.bytesToHex( buf ) );
   }
   
}

/**
 * Performs a short self-test of the Twofish cipher referring to standard test vectors.
 * @return <b>true</b> if data test vectors were confirmed for this algorithm
 */
public static boolean twofish_ecb () {
   byte[] key, pt, ct;
   boolean ok;
   
   try {   
      // Twofish algo selftesting
      ok = Twofish.self_test();
      if ( !ok ) {
         System.out.println( "*** Twofish algorithm selftest failed");
         return false;
      }
      
      // ECB TESTING
      // 128 key length
      key = new byte[ 16 ];
      pt = new byte[ 16 ];
      ct = Util.hexToBytes( "9F589F5CF6122C32B6BFEC2F2AE8C35A" );
      ok = test_ECB_vector( key, pt, ct );
      
      if ( ok ) {
         // permutation 1
         pt = ct;
         ct = Util.hexToBytes( "D491DB16E7B1C39E86CB086B789F5419" );
         ok = test_ECB_vector( key, pt, ct );
      }

      if ( ok ) {
         // permutation 2
         key = pt;
         pt = ct;
         ct = Util.hexToBytes( "019F9809DE1711858FAAC3A3BA20FBC3" );
         ok = test_ECB_vector( key, pt, ct );
      }

      if ( ok ) {
         // 192 key length
         key = Util.hexToBytes( "0123456789ABCDEFFEDCBA98765432100011223344556677" );
         pt = new byte[ 16 ];
         ct = Util.hexToBytes( "CFD1D2E5A9BE9CDF501F13B892BD2248" );
         ok = test_ECB_vector( key, pt, ct );
      }
      
      if ( ok ) {
         // 256 key length
         key = Util.hexToBytes( "0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF" );
         ct = Util.hexToBytes( "37527BE0052334B89F0CFCCAE87CFA20" );
         ok = test_ECB_vector( key, pt, ct );
      }
      
      if ( !ok ) {
         System.out.println( "*** Twofish ECB test failed");
         return false;
      }
/*      
      // CBC TESTING
      key = new byte[ 16 ];
      iv = new byte[ 16 ];
      pt = new byte[ 16 ];
      ct = Util.hexToBytes( "3CC3B181E1495D0495D652B66921DA0F" );
      ok = test_CBC_vector_E( key, iv, pt, ct );
*/      
   } catch ( Exception e ) {
      System.out.println( "*** SUNDRA TWOFISH TEST FAILURE");
      e.printStackTrace();
      return false;
   }
   
   return ok;
}

private static boolean test_ECB_vector ( byte[] key, byte[] pt, byte[] ct ) {
   TwofishCipher ci;
   byte[] ctt;
   boolean ok1, ok2;
   
   ci = new TwofishCipher( key );
   
   // encrypt direction
   ctt = ci.encrypt( pt );
   ok1 = Util.equalArrays( ct, ctt );
   
   // decrypt direction
   ctt = ci.decrypt( ct );
   ok2 = Util.equalArrays( pt, ctt );
   
   return ok1 & ok2;
}

public void test_twofish__CBC () {
	
	// create base cipher
	byte[] key = Util2.getCryptoRand().nextBytes(32);
	TwofishCipher ci = new TwofishCipher( key );

	// create CBC cipher
	byte[] iv = Util2.getCryptoRand().nextBytes( ci.getBlockSize() );
	CipherModeCBC cbc = new CipherModeCBC(ci, iv);
	
	byte[] pt = Util.randBytes(128);
	byte[] ct = cbc.encrypt(pt);
	
	CipherModeCBC cbc2 = new CipherModeCBC(ci, iv);
	byte[] cpt = cbc2.decrypt(ct);
	
	boolean ok = Util.equalArrays(pt, cpt);
	assertTrue("CBC encrypt/decrypt test failed", ok);
	
	// expected DIRECTION failure
	try {
		cbc.decrypt(ct);
		fail("missing exception for crypting DIRECTION");
	} catch (IllegalStateException e) {
	}

	// expected DIRECTION failure (encrypt)
	try {
		cbc2.encrypt(ct);
		fail("missing exception for crypting DIRECTION");
	} catch (IllegalStateException e) {
	}
}

public void test_twofish__CFB () {
	
	// create base cipher
	byte[] key = Util2.getCryptoRand().nextBytes(32);
	TwofishCipher ci = new TwofishCipher( key );
	int blocksize = ci.getBlockSize();

	// create CFB ciphers
	byte[] iv = Util2.getCryptoRand().nextBytes( blocksize );
	CipherModeCFB cbc = new CipherModeCFB(ci, iv);
	CipherModeCFB cbc2 = new CipherModeCFB(ci, iv);
	assertFalse("illegal isConsumed value (init)", cbc.isConsumed());
	assertTrue("IV retreival error (init)", Util.equalArrays(iv, cbc.getVector()));
	
	// TEST encryption/decryption of block-aligned random data
	byte[] pt = Util.randBytes(128);
	byte[] ct = cbc.encrypt(pt);
	byte[] cpt = cbc2.decrypt(ct);
	assertFalse("illegal isConsumed value (encrypted)", cbc.isConsumed());
	assertFalse("illegal isConsumed value (decrypted)", cbc2.isConsumed());
	
	boolean ok = Util.equalArrays(pt, cpt);
	assertTrue("CBC encrypt/decrypt ALIGNED DATA test failed", ok);
	
	// TEST IV vector after process
	byte[] iv2 = Util.arraycopy(ct, ct.length-blocksize, blocksize);
	assertTrue("IV retreival error (process)", Util.equalArrays(iv2, cbc.getVector()));
	assertTrue("IV retreival error (process)", Util.equalArrays(iv2, cbc2.getVector()));
	
	// TEST cipher direction failure (exception throwing)
	// expected DIRECTION failure (decrypt)
	try {
		cbc.decrypt(ct);
		fail("missing exception for crypting DIRECTION");
	} catch (IllegalStateException e) {
	}

	// expected DIRECTION failure (encrypt)
	try {
		cbc2.encrypt(ct);
		fail("missing exception for crypting DIRECTION");
	} catch (IllegalStateException e) {
	}
	
	// TEST unaligned data blocks : progress encryption
	pt = Util.randBytes(60);
	ct = cbc.encrypt(pt);
	cpt = cbc2.decrypt(ct);
	assertTrue("illegal isConsumed value (encrypted)", cbc.isConsumed());
	assertTrue("illegal isConsumed value (decrypted)", cbc2.isConsumed());

	ok = Util.equalArrays(pt, cpt);
	assertTrue("CBC encrypt/decrypt UNALIGNED DATA test failed", ok);
	
	// TEST after-consumed failure (exception throwing)
	try {
		cbc.encrypt(pt);
		fail("missing exception using consumed cipher");
	} catch (IllegalStateException e) {
	}
	try {
		cbc2.decrypt(ct);
		fail("missing exception using consumed cipher");
	} catch (IllegalStateException e) {
	}
}

public void test_performance () {
	PwsCipher ci1, ci2;
	
	ci1 = new TwofishCipher();
	test_cipher_performance(ci1);

	ci1 = new BlowfishCipher();
	test_cipher_performance(ci1);
	
	ci1 = new ScatterCipher();
	test_cipher_performance(ci1);
	
	ci1 = new NullCipher();
	test_cipher_performance(ci1);
}


private void test_cipher_performance(PwsCipher ci) {

	PwsCipher cbc = new CipherModeCBC(ci);
	int bs = cbc.getBlockSize();
	report("\nCIPHER-PERFORMANCE for ".concat(ci.getName()));
	
	// test 4 MB data 
	int length = 4000000 / bs * bs;
	byte[] data = Util.randBytes(length);
	long start = System.currentTimeMillis();
	byte[] ebuf = cbc.encrypt(data);
	long time = System.currentTimeMillis() - start;
	report("\n4,000,000 bytes block encryption: " + time + " ms");

	cbc = new CipherModeCBC(ci);
	start = System.currentTimeMillis();
	byte[] dbuf = cbc.decrypt(ebuf);
	time = System.currentTimeMillis() - start;
	report("\n4,000,000 bytes block decryption: " + time + " ms");
	report("\nCorrectness: " + Util.equalArrays(data, dbuf));

	// test 25 MB data 
	length = 25000000 / bs * bs;
	data = Util.randBytes(length);
	cbc = new CipherModeCBC(ci);
	start = System.currentTimeMillis();
	ebuf = cbc.encrypt(data);
	time = System.currentTimeMillis() - start;
	report("\n25,000,000 bytes block encryption: " + time + " ms");

	cbc = new CipherModeCBC(ci);
	start = System.currentTimeMillis();
	dbuf = cbc.decrypt(ebuf);
	time = System.currentTimeMillis() - start;
	report("\n25,000,000 bytes block decryption: " + time + " ms");
	report("\nCorrectness: " + Util.equalArrays(data, dbuf));

	report("\n");
}


private void report(String string) {
	System.out.print(string);
}

}
