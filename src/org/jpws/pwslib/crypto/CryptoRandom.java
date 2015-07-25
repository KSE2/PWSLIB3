/*
 *  CryptoRandom in org.jpws.pwslib.crypto
 *  file: CryptoRandom.java
 * 
 *  Project JPasswords
 *  @author Wolfgang Keller
 *  Created 02.09.2005
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

import java.awt.Dimension;
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
 * and random seed. The standard cycle period is 16.
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
 * @param cycle number of loops to use a single data pool incarnation
 */
public CryptoRandom ( int cycle )
{
   this( cycle, null );
}

/**
 * Constructs a random generator under taking into calculation user random 
 * seed data.
 * 
 * @param init initial random seed data (may be <b>null</b>
 */
public CryptoRandom ( byte[] init )
{
   init( init );
}

/**
 * Constructs a random generator with initial seed data and a definition of the 
 * pool refresh cycle loops. Higher values of <code>cycle</code> reduce execution 
 * cost but also might reduce long-term random quality.
 * 
 * @param cycle number of loops to use a single pool incarnation
 * @param init initial random seed data (may be <b>null</b>
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
      if ( init == null )
      {
         init = getUserSeed();
         if ( init != null & Log.getDebugLevel() >= 9 )
            Log.debug( 9, "(CryptoRandom) [" + instanceID + "] received user pool data, fingerprint: " 
                  + Util.bytesToHex( Util.fingerPrint( init )));
      }
      if ( init == null )
         init = userInit;
      if ( init != null )
      {
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
      tk = Toolkit.getDefaultToolkit();
      dim = tk.getScreenSize();
      dout.writeInt( tk.hashCode() );
      dout.writeInt( dim.height );
      dout.writeInt( dim.width );
      dout.writeInt( tk.getScreenResolution() );
      }
      catch ( Exception e )
      {}
      
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
   }
   catch ( IOException e )
   {
      System.err.println( "*** SEVERE ERROR IN INIT CRYPTORANDOM : " + e );
   }
   
}

/**
 * Callback function to obtain the user's random seed data array in an actual
 * version. You can override this in a subclass to supply seed data to this
 * generator.
 * <p>(This is an alternative method compared to <code>recollect()</code>.
 * This method updates the random pool data more reliably because it is a 
 * user-passive method, compared to  <code>recollect()</code> which is a user-active
 * method. However, frequent recollection may cost valuable time.)
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
 *  @param init user seed data or <b>null</b>
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
   
   if ( counter % loops == 0 )
      collectPool( null );
   
   prevData = Util.arraycopy( data );
   
   sha.update( pool );
   sha.update( buf );
   sha.finalize();
   buf = sha.digest();
   System.arraycopy( buf, 0, data, 0, hashLen );

   sha.reset();
   sha.update( Util.XOR_buffers( data, prevData ));
   sha.finalize();
   buf = sha.digest();
   System.arraycopy( buf, 0, data, hashLen, hashLen );
   pos = 0;

   if ( Log.getDebugLevel() >= 9 )
      Log.debug( 9, "(CryptoRandom) [" + instanceID + "] random data: " + 
            Util.bytesToHex( data ));
}

/** Returns a random <code>byte</code> value. */
public synchronized byte nextByte ()
{
   return nextByteIntern();
}

/** Returns a random <code>byte</code> value. */
private byte nextByteIntern ()
{
   if ( pos == data.length )
      recalculate();
      
   return data[ pos++ ];
}

/** Returns a random integer value ranging from 0 including to n excluding. 
 *  n must be positive. 
 */
public synchronized int nextInt ( int n )
{
   int bits, val;

   if (n<=0)
      throw new IllegalArgumentException("n <= 0");

   bits = nextIntIntern() & 0x7FFFFFFF;
   val = bits % n;

   return val;
}

/** Returns a random <code>int</code> value. The value ranges from 
 *  Integer.MINVALUE to Integer.MAXVALUE.
 */
public synchronized int nextInt ()
{
   return nextIntIntern();
}

/** Returns a random <code>long</code> value. */
public synchronized long nextLong ( )
{
   return ((long)nextIntIntern()) << 32 | nextIntIntern() ;
}

/**
 * Returns a random data byte array of the length as specified by the parameter.
 * 
 * @param num length of output byte array
 * @return random bytes
 */
public synchronized byte[] nextBytes ( int num )
{
   byte[] buf;
   int i;
   
   if ( num < 0 )
      throw new IllegalArgumentException("num < 0");
   
   buf = new byte[ num ];
   for ( i = 0; i < num; i++ )
      buf[i] = nextByteIntern();
   
   return buf;
}

/** Returns a random <code>boolean</code> value. */
public boolean nextBoolean ()
{
   return nextByte() < 0;
}

/** Returns a random <code>int</code> value. The value ranges from 
 *  Integer.MINVALUE to Integer.MAXVALUE.
 */
private int nextIntIntern ()
{
   return
   ((int)nextByteIntern() & 0xFF) << 24 |
   ((int)nextByteIntern() & 0xFF) << 16 |
   ((int)nextByteIntern() & 0xFF) <<  8 |
   ((int)nextByteIntern() & 0xFF);
}
}
