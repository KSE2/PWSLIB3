/*
 *  File: HashMac.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  @author Jeroen C. van Gelderen, Cryptix Foundation
 *  Created 2004
 * 
 *  Copyright (c) 2005-2015 by Wolfgang Keller, Munich, Germany
 *  Copyright (C) 1995-2000 The Cryptix Foundation Limited (modified)
 * 
 This program is copyright protected to the author(s) stated above. However, 
 you can use, redistribute and/or modify it for free under the terms of the 
 2-clause BSD-like license given in the document section of this project.  

 This program is distributed in the hope that it will be useful, but WITHOUT
 ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 FOR A PARTICULAR PURPOSE. See the license for more details.
*/

package org.jpws.pwslib.crypto;


import java.security.DigestException;


/**
 * This abstract class implements the block/padding structure as it is
 * used by sub-classing hashes.
 *
 * This class handles the message buffering, bit counting and padding.
 * Subclasses need implement only the three abstract functions to create a
 * working hash.
 *
 * This class has three padding modes: MD5-like, SHA-like and Tiger-like.
 * This applies to the padding and encoding of the 64-bit length counter.
 *
 * @version $Revision: 1.3 $
 * @author  Jeroen C. van Gelderen (gelderen@cryptix.org)
 *          <br>Modified by Wolfgang Keller, 2004
 */
public abstract class HashMac
{

// Constants
//...........................................................................

    private static final int DEFAULT_BLOCKSIZE = 64;


// Instance variables
//...........................................................................

    /** Size (in bytes) of the blocks. */
    private final int blockSize;


    /** Size (in bytes) of the digest */
    private final int hashSize;


    /** 64 byte buffer */
    private final byte[] buf;


    /** Buffer offset */
    private int bufOff;


    /** Number of bytes hashed 'till now. */
    private long byteCount;


    /** Mode */
    private final int mode;

    /** stored result value */
    private byte[] result;

    protected static final int
        MODE_MD    = 0,
        MODE_SHA   = 1,
        MODE_TIGER = 2;


// Constructors
//...........................................................................


    /**
     * Construct a 64-byte HashMac in MD-like, SHA-like or Tiger-like
     * padding mode.
     *
     * The subclass must call this constructor, giving the length of it's hash
     * in bytes.
     *
     * @param hashSize  Length of the hash in bytes
     * @param mode      padding mode (MODE_MD, MODE_SHA, MODE_TIGER)
     */
    protected HashMac (int hashSize, int mode)
    {
        this( DEFAULT_BLOCKSIZE, hashSize, mode );
    }


    /**
     * Construct HashMac with 64 or 128-byte blocksize in MD-like, SHA-like or 
     * Tiger-like padding mode.
     *
     * @param blockSize 64 or 128
     * @param hashSize  Length of the hash in bytes.
     * @param mode      padding mode (MODE_MD, MODE_SHA, MODE_TIGER)
     */
    protected HashMac (int blockSize, int hashSize, int mode)
    {
        if( blockSize != 64 && blockSize != 128 )
            throw new RuntimeException("blockSize must be 64 or 128!");

        this.blockSize = blockSize;
        this.hashSize  = hashSize;
        this.buf       = new byte[blockSize];
        this.bufOff    = 0;
        this.byteCount = 0;
        this.mode      = mode;
    }

    protected HashMac ( HashMac src ) 
    {
       this.blockSize = src.blockSize;
       this.hashSize  = src.hashSize;
       this.buf       = (byte[])src.buf.clone();
       this.bufOff    = src.bufOff;
       this.byteCount = src.byteCount;
       this.mode      = src.mode;
       this.result    = src.result;
   }

    /**
     * Cloning is organized by descendant classes through constructors.
     * (Required because of finals in member data.)
     */
    @Override
	protected Object clone() throws CloneNotSupportedException 
    {
       throw new CloneNotSupportedException();
   }



// Implementation
//...........................................................................

    public int getDigestLength()
    {
        return this.hashSize;
    }

    public int getBlockSize ()
    {
       return blockSize;
    }
    
    public void update( byte input )
    {
       if ( result != null )
          throw new IllegalStateException("instance used up");
       
       //#ASSERT(this.bufOff < blockSize);

        byteCount += 1;
        buf[bufOff++] = input;
        if( bufOff==blockSize ) {
            coreUpdate(buf, 0);
            bufOff = 0;
        }

        //#ASSERT(this.bufOff < blockSize);
    }

    public void update( int input )
    {
       for ( int i = 3; i > -1; i-- )
          update( (byte)(input >>> i*8) );
    }
    
    public void update( long input )
    {
       for ( int i = 1; i > -1; i-- )
          update( (int)(input >>> i*32) );
    }
    
    public void update( byte[] input )
    {
       update( input, 0, input.length );
    }
    
    public void update( byte[] input, int offset, int length )
    {
       if ( offset + length > input.length )
          throw new IllegalArgumentException( "length overflow" );
       
       if ( result != null )
          throw new IllegalStateException("instance used up");
       
        byteCount += length;

        //#ASSERT(this.bufOff < blockSize);

        int todo;
        while( length >= (todo = blockSize - this.bufOff) ) 
        {
            System.arraycopy(input, offset, this.buf, this.bufOff, todo);
            coreUpdate(this.buf, 0);
            length -= todo;
            offset += todo;
            this.bufOff = 0;
        }

        //#ASSERT(this.bufOff < blockSize);

        System.arraycopy(input, offset, this.buf, this.bufOff, length);
        bufOff += length;
    }

    public void update( char[] input )
    {
       update( input, 0, input.length );
    }
    
    /**
     * Update sees an array of chars as a sequence of bytes as they are stored,
     * which means each char as 2 bytes in Big-Endian order (most significant 
     * stored first).
     * 
     * @param input a char array
     * @param offset start offset in <code>input</coe>
     * @param length number of chars to be used for this update
     */
    public void update( char[] input, int offset, int length )
    {
       int i;
       char c;
       
       if ( offset + length > input.length )
          throw new IllegalArgumentException( "length overflow" );
       
       for ( i = 0; i < length; i++ )
       {
          c = input[ offset + i ];
          update( (byte)(c >>> 8) );
          update( (byte)c );
       }
    }
    
    /**
     * Update sees a <code>String</code> as a sequence of chars as if they 
     * were an array of chars derived with <code>input.toCharArray()</code>.
     * 
     * @param input a String
     */
    public void update( String input )
    {
       update( input, 0, input.length() );
    }
    
    /**
     * Update sees a <code>String</code> segment as a sequence of chars as if they 
     * were an array of chars derived with 
     * <code>input.substring(offset,offset+length).toCharArray()</code>.
     * 
     * @param input a String
     * @param offset start offset in <code>input</code>
     * @param length number of chars to be used for this update
     */
    public void update( String input, int offset, int length )
    {
       int i;
       char c;

       if ( offset + length > input.length() )
          throw new IllegalArgumentException( "length overflow" );
       
       for ( i = 0; i < length; i++ )
       {
          c = input.charAt( offset + i );
          update( (byte)(c >>> 8) );
          update( (byte)c );
       }
    }
    
    public byte[] digest()
    {
        byte[] tmp = new byte[hashSize];
        privateDigest(tmp, 0, hashSize);
        return tmp;
    }


    public int readDigest( byte[] buf, int offset, int len )
    throws DigestException
    {
        if ( len<0 || len>hashSize )
           throw new DigestException();

        return privateDigest(buf, offset, len);
    }


    /**
     * Same as protected int digest(byte[] buf, int offset, int len)
     * except that we don't validate arguments.
     */
    private int privateDigest(byte[] buf, int offset, int len)
    {
       //#ASSERT(this.bufOff < blockSize);
       
       // calculate value only if no result stored
       if ( result == null )
       {
          this.buf[this.bufOff++] = (mode==MODE_TIGER) ? (byte)0x01 : (byte)0x80;
          
          int lenOfBitLen = (blockSize==128) ? 16 : 8;
          int C = blockSize - lenOfBitLen;
          if ( this.bufOff > C ) 
          {
             while ( this.bufOff < blockSize )
                this.buf[ this.bufOff++ ] = (byte)0x00;
             
             coreUpdate( this.buf, 0 );
             this.bufOff = 0;
          }
          
          while ( this.bufOff < C )
             this.buf[ this.bufOff++ ] = (byte)0x00;
          
          long bitCount = byteCount * 8;
          if (blockSize==128)
             for (int i=0; i<8; i++)
                this.buf[ this.bufOff++ ] = 0x00;
          
          if (mode==MODE_SHA) {
             // 64-bit length is appended in big endian order
             for (int i=56; i>=0; i-=8)
                this.buf[this.bufOff++] = (byte)(bitCount >>> (i) );
          } else {
             // 64-bit length is appended in little endian order
             for(int i=0; i<64; i+=8)
                this.buf[this.bufOff++] = (byte)(bitCount >>> (i) );
          }
          
          coreUpdate(this.buf, 0);
          result = new byte[ hashSize ];
          coreDigest(result, 0);
       }        
    
       // return hash value
       System.arraycopy( result, 0, buf, offset, len );
       return hashSize;
    }

    /** Finalize of this class destroys a resulting digest value. */
    @Override
	public void finalize ()
    {
       if ( result != null )
          for ( int i = 0; i < result.length; i++ )
             result[ i ] = 0;
    }

    public void reset() 
    {
        bufOff    = 0;
        byteCount = 0;
        result = null; 
        coreReset();
    }

// Delegated methods
//...........................................................................

    /**
     * Return the hash bytes in <code>buf</code>, starting at offset
     * <code>off</code>.
     *
     * The subclass is expected to write exactly <code>hashSize</code> bytes
     * in the given buffer. The buffer is guaranteed to be large enough.
     */
    protected abstract void coreDigest(byte[] buf, int off);


    /**
     * Reset the hash internal structures to initial state.
     */
    protected abstract void coreReset();


    /**
     * Update the internal state with a single block.
     *
     * <code>buf</code> contains a single block (64 bytes, 512 bits) of data,
     * starting at offset <code>off</code>.
     */
    protected abstract void coreUpdate(byte[] buf, int off);
}