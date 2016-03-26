/*
 *  File: CryptoRandom.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 02.09.2005
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

package org.jpws.pwslib.crypto;

import java.awt.Dimension;
import java.awt.MouseInfo;
import java.awt.Point;
import java.awt.Toolkit;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Random;

import org.jpws.pwslib.global.Log;
import org.jpws.pwslib.global.Util;

/**
 *  Enhanced random generator for cryptographical purposes. Claims to be 
 *  thread-safe. 
 *  <p>This random generator is based on the SHA-512 function which is assumed 
 *  to generate a set of cryptologically qualifying random values on any given
 *  data pool. The variance of the data pool is acquired by a mixture of 
 *  counter increment and cyclic recollection of various system and application
 *  specific data which can be expected to shape into a random state by each call.
 *  <p>Instances can be used straight away and the dominant seed sources
 *  will be time, system memory constellation and "usual" random values of <code>
 *  java.util.Random</code>. A good job should be expected by only this. However,
 *  an opening for additional user pool data exists with method <code>getUserSeed()
 *  </code>. It is called with every data pool refresh (cycle period) and
 *  can be activated through overriding in a subclass of this. Applications which
 *  are in hold of real random values on a regular basis can meaningfully use
 *  this feature.   
 */
public class CryptoRandom
{
   private static long timerstart = System.currentTimeMillis();
   private static int instanceCounter;
   
   private int instanceID;
   private Random rand = new Random();

   private byte[] pool;
   private byte[] data = new byte[ 2 * SHA512.HASH_SIZE ];
   private byte[] userInit;
   private long counter;
   private int loops = 8;
   private int pos;
   

/**
 * Constructs a random generator under standard values for refresh cycle 
 * and random seed. The default cycle period is 8.
 */
public CryptoRandom ()
{
   init( null );
}

/**
 * Constructs a random generator with user definition of the pool refresh cycle
 * loops. Higher values of <code>cycle</code> reduce execution cost but
 * also might reduce long-term random quality.
 * 
 * @param cycle int number of loops to use a single data pool incarnation
 */
public CryptoRandom ( int cycle )
{
   this( cycle, null );
}

/**
 * Constructs a random generator under taking into calculation user random 
 * seed data. The default cycle period is 8.
 * 
 * @param init byte[] initial random seed data, may be <b>null</b>
 */
public CryptoRandom ( byte[] init )
{
   init( init );
}

/**
 * Constructs a random generator with initial seed data and a definition of the 
 * pool refresh cycle loops. Higher values of <code>cycle</code> reduce 
 * execution cost but also might reduce long-term random quality.
 * 
 * @param cycle int number of loops to use a single pool incarnation
 * @param init byte[] initial random seed data (may be <b>null</b>)
 */
public CryptoRandom ( int cycle, byte[] init )
{
   if ( cycle < 1 )
      throw new IllegalArgumentException();
   
   loops = cycle;
   init( init );
}

private void init ( byte[] init )
{
   instanceID = instanceCounter++;
   rand.nextBytes( data );
   collectPool( init );
   recalculate();
}

private void collectPool ( byte[] init )
{
   Toolkit tk;
   Dimension dim;
   ByteArrayOutputStream out;
   DataOutputStream dout;
   Runtime rt;
   byte[] buf;
   long now;
   
   if ( Log.getLogLevel() >= 9 )
   Log.log( 9, "(CryptoRandom) [" + instanceID + "] collecting pool data" );

   // collect random pool data
   out = new ByteArrayOutputStream();
   dout = new DataOutputStream( out );
   try {
      // the current data
      dout.write( data );
      
      // current time related
      now = System.currentTimeMillis();
      dout.writeLong( now );
      dout.writeLong( now - timerstart );
      
      // "normal" random bytes (40)
      buf = new byte[ 40 ];
      rand.nextBytes( buf );
      dout.write( buf );
      
      // user seed if available 
      if ( init == null ) {
         init = getUserSeed();
         if ( init != null & Log.getDebugLevel() >= 9 ) {
            Log.debug( 9, "(CryptoRandom) [" + instanceID + "] received user pool data, fingerprint: " 
                  + Util.bytesToHex( Util.fingerPrint( init )));
         }
      }
      if ( init == null ) {
         init = userInit;
      }
      if ( init != null ) {
         dout.write( init );
         userInit = init;
      }
      
      // current thread address
      dout.writeInt( Thread.currentThread().hashCode() );
      
      // memory status
      rt = Runtime.getRuntime();
      dout.writeLong( rt.totalMemory() );
      dout.writeLong( rt.maxMemory() );
      dout.writeLong( rt.freeMemory() );
      
      // screen related
      try {
    	  // screen dimension data
	      tk = Toolkit.getDefaultToolkit();
	      dim = tk.getScreenSize();
	      dout.writeInt( tk.hashCode() );
	      dout.writeInt( dim.height );
	      dout.writeInt( dim.width );
	      dout.writeInt( tk.getScreenResolution() );
	      
	      // mouse position
	      Point p = MouseInfo.getPointerInfo().getLocation();
	      dout.writeInt(p.x);
	      dout.writeInt(p.y);
	      
      } catch ( Exception e ) {
      }
      
      // this instance 
      dout.writeInt( this.hashCode() );
      
      // system properties
      dout.writeBytes( System.getProperty( "java.class.path", "" ) );
      dout.writeBytes( System.getProperty( "java.library.path", "" ) );
      dout.writeBytes( System.getProperty( "java.vm.version", "" ) );
      dout.writeBytes( System.getProperty( "os.version", "" ) );
      dout.writeBytes( System.getProperty( "user.dir", "" ) );
      dout.writeBytes( System.getProperty( "user.name", "" ) );
      dout.writeBytes( System.getProperty( "user.timezone", "" ) );
      
      // store collection
      pool = out.toByteArray();

      if ( Log.getDebugLevel() >= 9 )
      Log.debug( 9, "(CryptoRandom) [" + instanceID + "] pool data fingerprint: " 
            + Util.bytesToHex( Util.fingerPrint( pool )));

   } catch ( IOException e ) {
      System.err.println( "*** SEVERE ERROR IN INIT CRYPTORANDOM : " + e );
   }
   
}

/**
 * Callback function to obtain the user's random seed data array in a subclass.
 * You can override this to supply specific seed data to this generator.
 * <p>(This is an alternative method compared to <code>recollect()</code>.
 * This method updates the random pool data more reliably because it is a 
 * user-passive method, compared to  <code>recollect()</code> which is a 
 * user-active method. However, frequent recollection may be expensive in time.)
 * 
 * @return byte[] random seeds
 */
public byte[] getUserSeed ()
{
   return null;
}

/** Causes this random generator to collect a new random data pool including
 *  the user's seed data as given by the parameter.
 * 
 *  @param init byte[] user seed data or <b>null</b>
 */
public synchronized void recollect ( byte[] init )
{
   collectPool( init );
}

/** Creates a new 2*HASHSIZE bytes random data block. */
private void recalculate ()
{
   SHA512 sha;
   byte[] buf, prevData;
   int hashLen;
   
   if ( Log.getLogLevel() >= 9 )
   Log.log( 9, "(CryptoRandom) [" + instanceID + "] recalculating random: " + counter );
   
   sha = new SHA512();
   hashLen = sha.getDigestLength();
   buf = new byte[8];
   Util.writeLong( counter++, buf, 0 );
   
   if ( counter % loops == 0 ) {
      collectPool( null );
   }
   
   prevData = Util.arraycopy( data );
   
   sha.update( pool );
   sha.update( buf );
   buf = sha.digest();
   System.arraycopy( buf, 0, data, 0, hashLen );

   sha.reset();
   sha.update( Util.XOR_buffers( data, prevData ));
   buf = sha.digest();
   System.arraycopy( buf, 0, data, hashLen, hashLen );
   pos = 0;

   if ( Log.getDebugLevel() >= 9 ) 
   Log.debug( 9, "(CryptoRandom) [" + instanceID + "] random data: " + Util.bytesToHex( data ));
}

/** Returns a random <code>byte</code> value.
 * 
 *  @return byte
 */
public synchronized byte nextByte ()
{
   return nextByteIntern();
}

/** Returns a random <code>byte</code> value. 
 * 
 *  @return byte
 */
private byte nextByteIntern ()
{
   if ( pos == data.length ) {
      recalculate();
   }
      
   return data[ pos++ ];
}

/** Returns a random integer value ranging from 0 including to n excluding. 
 *  n must be positive. 
 *  
 *  @param n int size of value range 
 *  @return int random value
 */
public synchronized int nextInt ( int n )
{
   if (n<=0)
      throw new IllegalArgumentException("n <= 0");

   int bits = nextIntIntern();
   bits = (bits < 0) ? -bits : bits;
   int val = bits % n;
   return val;
}

/** Returns a random <code>int</code> value. The value ranges from 
 *  Integer.MINVALUE to Integer.MAXVALUE.
 * 
 *  @return int random value
 */
public synchronized int nextInt ()
{
   return nextIntIntern();
}

/** Returns a random <code>long</code> value. 
 * 
 *  @return long random value
 */
public synchronized long nextLong ( )
{
   return ((long)nextIntIntern() << 32) | ((long)nextIntIntern() & 0xFFFFFFFFL);
}

/**
 * Returns a random data byte array of the length as specified by the parameter.
 * 
 * @param num int length of output byte array
 * @return byte[] random bytes
 */
public synchronized byte[] nextBytes ( int num )
{
   if ( num < 0 )
      throw new IllegalArgumentException("num < 0");
   
   byte[] buf = new byte[ num ];
   for ( int i = 0; i < num; i++ ) {
      buf[i] = nextByteIntern();
   }
   
   return buf;
}

/** Returns a random <code>boolean</code> value. 
 * 
 *  @return boolean random value
 */
public boolean nextBoolean ()
{
   return nextByte() < 0;
}

/** Returns a random <code>int</code> value. The value ranges from 
 *  Integer.MINVALUE to Integer.MAXVALUE.
 * 
 *  @return int random value
 */
private int nextIntIntern ()
{
   return
   (int)nextByteIntern() << 24 |
   ((int)nextByteIntern() & 0xFF) << 16 |
   ((int)nextByteIntern() & 0xFF) <<  8 |
   ((int)nextByteIntern() & 0xFF);
}
}
