/* $Id: SHA512.java,v 1.2 2006/09/10 07:35:19 Besitzer Exp $
 *
 * Copyright (C) 2000 The Cryptix Foundation Limited. All rights reserved.
 *
 * Use, modification, copying and distribution of this software is subject to
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 *
 * Modified: Wolfgang Keller, 2004 for the JQB project
 * Version 0.0.4
 */

package org.jpws.pwslib.crypto;

import org.jpws.pwslib.global.Util;



/**
 * @version $Revision: 1.2 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 *          <br>Modified by Wolfgang Keller, 2006
 */
public class SHA512 extends HashMac implements Cloneable
{

// Constants
//...........................................................................

private static final int BLOCK_SIZE = 128;

/** Size (in bytes) of this hash */
public static final int HASH_SIZE = 64;

/** Round constants */
private static final long K[] = {
    0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL,
    0xe9b5dba58189dbbcL, 0x3956c25bf348b538L, 0x59f111f1b605d019L,
    0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L, 0xd807aa98a3030242L,
    0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
    0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L,
    0xc19bf174cf692694L, 0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L,
    0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L, 0x2de92c6f592b0275L,
    0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
    0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL,
    0xbf597fc7beef0ee4L, 0xc6e00bf33da88fc2L, 0xd5a79147930aa725L,
    0x06ca6351e003826fL, 0x142929670a0e6e70L, 0x27b70a8546d22ffcL,
    0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
    0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L,
    0x92722c851482353bL, 0xa2bfe8a14cf10364L, 0xa81a664bbc423001L,
    0xc24b8b70d0f89791L, 0xc76c51a30654be30L, 0xd192e819d6ef5218L,
    0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L,
    0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L,
    0x34b0bcb5e19b48a8L, 0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL,
    0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L, 0x748f82ee5defb2fcL,
    0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
    0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L,
    0xc67178f2e372532bL, 0xca273eceea26619cL, 0xd186b8c721c0c207L,
    0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L, 0x06f067aa72176fbaL,
    0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL,
    0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL,
    0x431d67c49c100d4cL, 0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL,
    0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L
};


// Instance variables
//...........................................................................

    /** 8 64-bit words (interim result) */
    private final long[] context;

    /** Expanded message block buffer */
    private final long[] buffer;



// Constructors
//...........................................................................

    public SHA512 ()
    {
        super(BLOCK_SIZE, HASH_SIZE, HashMac.MODE_SHA);
        this.context = new long[8];
        this.buffer  = new long[80];
        coreReset();
    }

    private SHA512 ( SHA512 src )
    {
       super( src );
       this.context = (long[])src.context.clone();
       this.buffer  = (long[])src.buffer.clone();
    }


    public Object clone() 
    {
       return new SHA512(this);
    }


// Concreteness
//...........................................................................

    /** Returns the resulting hash value in 64 bytes from offset.
     */
    protected void coreDigest (byte[] buf, int off)
    {
        for( int i=0; i<context.length; i++ )
            for( int j=0; j<8 ; j++ )
                buf[off+(i * 8 + (7-j))] = (byte)(context[i] >>> (8 * j));
    }


    protected void coreReset()
    {
        // initial values
       context[0] = 0x6a09e667f3bcc908L;
       context[1] = 0xbb67ae8584caa73bL;
       context[2] = 0x3c6ef372fe94f82bL;
       context[3] = 0xa54ff53a5f1d36f1L;
       context[4] = 0x510e527fade682d1L;
       context[5] = 0x9b05688c2b3e6c1fL;
       context[6] = 0x1f83d9abfb41bd6bL;
       context[7] = 0x5be0cd19137e2179L;
    }


    protected void coreUpdate(byte[] block, int offset) 
    {
       long[] W = buffer;

       // extract the bytes into our working buffer
       for( int i=0; i<16; i++ )
           W[i] = ((long)block[offset++]       ) << 56 |
                  ((long)block[offset++] & 0xFF) << 48 |
                  ((long)block[offset++] & 0xFF) << 40 |
                  ((long)block[offset++] & 0xFF) << 32 |
                  ((long)block[offset++] & 0xFF) << 24 |
                  ((long)block[offset++] & 0xFF) << 16 |
                  ((long)block[offset++] & 0xFF) <<  8 |
                  ((long)block[offset++] & 0xFF);

       // expand
       for( int i=16; i<80; i++ )
           W[i] = sig1(W[i-2]) + W[i-7] + sig0(W[i-15]) + W[i-16];

       long a = context[0];
       long b = context[1];
       long c = context[2];
       long d = context[3];
       long e = context[4];
       long f = context[5];
       long g = context[6];
       long h = context[7];

       // run 80 rounds
       for( int i=0; i<80; i++ ) {
           long T1 = h + Sig1(e) + Ch(e, f, g) + K[i] + W[i];
           long T2 = Sig0(a) + Maj(a, b, c);
           h = g;
           g = f;
           f = e;
           e = d + T1;
           d = c;
           c = b;
           b = a;
           a = T1 + T2;
       }

       // merge
       context[0] += a;
       context[1] += b;
       context[2] += c;
       context[3] += d;
       context[4] += e;
       context[5] += f;
       context[6] += g;
       context[7] += h;
   }

//  Helpers
//  ...........................................................................

    private final long Ch(long x, long y, long z) { return (x&y)^(~x&z); }

    private final long Maj(long x, long y, long z) { return (x&y)^(x&z)^(y&z); }

    private final long Sig0(long x) { return S(28, x) ^ S(34, x) ^ S(39, x); }
    private final long Sig1(long x) { return S(14, x) ^ S(18, x) ^ S(41, x); }
    private final long sig0(long x) { return S( 1, x) ^ S( 8, x) ^ R( 7, x); }
    private final long sig1(long x) { return S(19, x) ^ S(61, x) ^ R( 6, x); }

    private final long R(int off, long x) { return (x >>> off); }
    private final long S(int off, long x) { return (x>>>off) | (x<<(64-off)); }

    
   public static boolean self_test ()
   {
      SHA512 s1, s2, s3, s4, s5;
      byte[] ba;
      int i;
      String hstr, ctv;
      
      s1 = new SHA512(); 
      s2 = new SHA512(); 
      s3 = new SHA512(); 
      s4 = new SHA512(); 
      s5 = new SHA512(); 
   
      // length
      if ( s1.getDigestLength() != 64 )
      {
         System.out.println( "SHA-512 failure: digest length == 64" );
         return false;
      }
      
      // Test value "blank"
      hstr = Util.bytesToHex( s1.digest() );
      ctv = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
      if ( !hstr.equals( ctv ) )
      {
         System.out.println( "SHA-512 failure: conforming \"blank\" result" );
         return false;
      }
      
      // Test value "empty"
      s2.update( "".getBytes() );
      hstr = Util.bytesToHex( s2.digest() );
      if ( !hstr.equals( ctv ) )
      {
         System.out.println( "SHA-512 failure: conforming \"empty\" result" );
         return false;
      }
     
      // Test value NIST C.1 ("abc")
      s3.update( "abc".getBytes() );
      hstr = Util.bytesToHex( s3.digest() );
      ctv = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
      if ( !hstr.equals( ctv ) )
      {
         System.out.println( "SHA-512 failure: conforming \"C.1\" result" );
         return false;
      }
      
      // Test value NIST C.2
      hstr = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
      s4.update( hstr.getBytes() );
      hstr = Util.bytesToHex( s4.digest() );
      ctv = "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909";
      if ( !hstr.equals( ctv ) )
      {
         System.out.println( "SHA-512 failure: conforming \"C.2\" result" );
         return false;
      }
   
      // Test value NIST C.3 ("a" * 1000000) 
      ba = new byte[1000];
      for ( i = 0; i < 1000; i++ )
         ba[i] = 'a';
      for ( i = 0; i < 1000; i++ )
         s5.update( ba );
      hstr = Util.bytesToHex( s5.digest() );
      ctv = "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b";
      if ( !hstr.equals( ctv ) )
      {
         System.out.println( "SHA-512 failure: conforming \"C.3\" result" );
         return false;
      }
   
      return true;
   }  // self_test
   
   public static byte[] seedDigest ( long seed )
   {
      SHA512 sha = new SHA512();
      int i;
      
      for ( i = 0; i < 8; i++ )
         sha.update( (byte)(seed >>> i) );
      return sha.digest();
   }

}
