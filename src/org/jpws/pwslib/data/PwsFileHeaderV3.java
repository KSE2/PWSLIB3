/*
 *  file: PwsFileHeaderV2.java
 * 
 *  Project JPasswords
 *  @author Wolfgang Keller
 *  Created 07.08.2005
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

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Iterator;

import org.jpws.pwslib.crypto.CryptoRandom;
import org.jpws.pwslib.crypto.PwsCipher;
import org.jpws.pwslib.crypto.SHA256;
import org.jpws.pwslib.crypto.TwofishCipher;
import org.jpws.pwslib.exception.UnsupportedFileVersionException;
import org.jpws.pwslib.global.Global;
import org.jpws.pwslib.global.Log;
import org.jpws.pwslib.global.PwsChecksum;
import org.jpws.pwslib.global.UUID;
import org.jpws.pwslib.global.Util;
import org.jpws.pwslib.persist.V3_InputStream;


/**
 * This class represents the header fields of a <b>PasswordSafe V3</b> database
 * (persistent state) and allows to obtain objects enabling to read the
 * remainder of the file in a decrypted fashion or to save the header to a new 
 * persistent state. 
 *   
 * <p>The original format definition of V3 files is available under document name: "PWS Format V3.txt"
 * in the document folder of the developer download package.   

 * <p>This version of the class complies to PWS format definition 3.6. There is one
 * additional field added as feature for JPWS: <tt>JPWS_OPTIONS_TYPE</tt>. Files created
 * with this header will assert themselves as of this format version.
 * 
 * @since 2-0-0
 * @since last modified 2-2-0
 * @author Wolfgang Keller
 */
public class PwsFileHeaderV3
{
   /** Field type code for the JPWS-options header field. */
   public static final int JPWS_OPTIONS_TYPE = 0x40;

   /** Field type code for the PWS-preferences header field. */
   public static final int PWS_PREFS_TYPE = 0x02;

   /** Field type code for the file-UUID header field. */
   public static final int FILE_UUID_TYPE = 0x01;

   /** Field type code for the PWS tree-display data header field. */
   public static final int TREE_DISPLAY_TYPE = 0x03;

   /** Field type code for the save time-stamp header field. 
   * @since 2-1-0 
   */
   public static final int SAVETIME_TYPE = 0x04;
   
   /** Field type code for the application name stamp (header field). 
   * @since 2-1-0 
   */
   public static final int APPLICATION_TYPE = 0x06;
   
   /** Field type code for the save person stamp header field. 
   * @since 2-1-0 
   */
   public static final int OPERATOR_TYPE = 0x07;
   
   /** Field type code for the save person stamp header field. 
   * @since 2-1-0 
   */
   public static final int HOST_TYPE = 0x08;
   
   /** Field type code for the file name header field. 
   * @since 2-1-0 
   */
   public static final int FILE_NAME_TYPE = 0x09;
   
   /** Field type code for the file name header field. 
   * @since 2-1-0 
   */
   public static final int FILE_DESCRIPTION_TYPE = 0x0a;
   
   /** Field type code for the file format version field. 
    * @since 2-2-0 
    */
   public static final int FILE_FORMAT_TYPE = 0x0;
    
   /** Field type code for the "recently used entries" header field. 
    * @since 2-2-1 
    */
   public static final int RECENT_ENTRIES_TYPE = 0x0f;
     
   /** Field type code for the file format version field. 
    * @since 2-2-0 
    */
   public static final int NAMED_POLICIES_TYPE = 0x10;
      
   /** Field type code for the last PWS 3 canonical header field. 
   * @since 2-1-0 
   */
   public static final int LAST_STANDARD_HEADER_FIELD = 0x10;

   /** Internal constant for database version identification. */
   private static final byte[] PWS3_FILEID = { 'P', 'W', 'S', '3' };
   private static final byte[] V3VERSION = { 
      Global.FILEVERSION_LATEST_MINOR, Global.FILEVERSION_LATEST_MAJOR };
   
   // FIX LENGTH VALUE CODES (as documented): TAG|SALT|ITER|H(P')|B1|B2|B3|B4|IV
   // length: 152 bytes
   private byte [] tag	= new byte[  4 ];  // PWS file ID      
   private byte [] salt = new byte[ 32 ];  // initial random value
   private int     iter = 4096;            // iteration value (4 byte integer LE)
   private byte [] hpm	= new byte[ 32 ];  // key validator hash
   private byte [] b12  = new byte[ 32 ];  // encrypted cipher key
   private byte [] b34  = new byte[ 32 ];  // encrypted checksum seed (hmac) 
   private byte [] iv   = new byte[ 16 ];  // CBC mode init value
   
   // HDR field list
   private HeaderFieldList hdrFields = new HeaderFieldList();
   
   // admin
   private boolean isRead;
   private byte[] hseed;
   private boolean isVerified;

   private InputStream input;
   private BlockInputStream blockStream;
   private V3_InputStream v3In;
   private PwsChecksum writeHmac;
   private PwsChecksum readHmac;
   
    /**
     * Creates an empty V3 file header. This may be used to create a new PWS file
     * of the V3 format.
     */
    public PwsFileHeaderV3()
    {
       this( (HeaderFieldList)null );
    }

   /**
	 * Creates a V3 file header including the parameter header
     * field list to be saved. 
     * This may be used to create a new PWS file of the V3 format.
     * 
     * @param headerFields <code>HeaderFieldList</code> file header data-fields;
     *        may be <b>null</b>
	 */
	public PwsFileHeaderV3( HeaderFieldList headerFields )
	{
       Log.log( 5, "(PwsFileHeaderV3) initializer (headerFields)" );
       if ( headerFields != null )
          hdrFields = headerFields;

       ensureHeaderDefaults();
	}

    /* Writes actual values to some of the standard header fields;
     * ensures existence and correct values of minimum header fields.
     * (** Currently this suppresses header fields for identification
     * of operator and host. **)
     *    
     * @since 2-1-0 
     */
    private void ensureHeaderDefaults ()
    {
       PwsRawField raw;
       
       Log.log( 5, "(PwsFileHeaderV3) ensureHeaderDefaults, 0" );

       // remove deprecated fields
       removeHeaderField( 0x05 );  // old user/host combination as of PWS V3.1
       
       // force file format version marker
//       Log.log( 5, "(PwsFileHeaderV3) ensureHeaderDefaults, 1" );
       setHeaderField( new PwsRawField( 0, V3VERSION ) );
       
       // application name (of last save)
//       Log.log( 5, "(PwsFileHeaderV3) ensureHeaderDefaults, 2" );
       setHeaderField( PwsRawField.makeTextField( APPLICATION_TYPE, Global.getProgramName() ));
       
       // operator name (of last save)
//       Log.log( 5, "(PwsFileHeaderV3) ensureHeaderDefaults, 3" );
       setHeaderField( PwsRawField.makeTextField( OPERATOR_TYPE, System.getProperty( "user.name" ) ) );

       // host name (of last save)  ** UNUSED / ERASE **
       // currently we bring the OS name here
//       Log.log( 5, "(PwsFileHeaderV3) ensureHeaderDefaults, 4" );
       setHeaderField( PwsRawField.makeTextField( HOST_TYPE, 
             System.getProperty( "os.name" ) + " " + System.getProperty( "os.version" ) ) );

       // time of last save
//       Log.log( 5, "(PwsFileHeaderV3) ensureHeaderDefaults, 5, time = " + System.currentTimeMillis() );
       raw = PwsRawField.makeTimeField( SAVETIME_TYPE, System.currentTimeMillis(), 4 );
//       Log.log( 5, "(PwsFileHeaderV3) ensureHeaderDefaults, 5.1" );
       setHeaderField( raw );

       // ensure file-ID
//       Log.log( 5, "(PwsFileHeaderV3) ensureHeaderDefaults, 6" );
       if ( getFileID() == null )
       {
//          Log.log( 5, "(PwsFileHeaderV3) ensureHeaderDefaults, 7" );
          setHeaderField( new PwsRawField( FILE_UUID_TYPE, new UUID().getBytes() ) );
       }
       Log.log( 5, "(PwsFileHeaderV3) ensureHeaderDefaults, exit" );
    }
    
	/**
	 * Constructs a PWS V3 file header by reading the header data 
    * from the parameter inputstream. (This is the mandatory constructor
    * to perform passphrase verification.)  
	 * 
	 * @param input java.io.InputStream, placed at the beginning of a PWS file
	 * 
	 * @throws IOException if an error occurs while reading from the stream
     * @throws UnsupportedFileVersionException if the file is not a V3 file
	 */
	public PwsFileHeaderV3( InputStream input )  
       throws IOException, UnsupportedFileVersionException
	{
       this();
       
       DataInputStream in;
       byte[] buf;

       this.input = input;
       in = new DataInputStream( input );

       // read the core header values
       in.readFully( tag );

       if ( !Util.equalArrays( tag, PWS3_FILEID ) )
          throw new UnsupportedFileVersionException();
       
       in.readFully( salt );

       buf = new byte[ 4 ];
       in.readFully( buf );
       iter = Util.readIntLittle( buf, 0 );
       
       in.readFully( hpm );
       in.readFully( b12 );
       in.readFully( b34 );
       in.readFully( iv );

       isRead = true;
       Log.log( 5, "(PwsFileHeaderV3) file header read: " + Util.bytesToHex( salt ));
	}

    /**
     * Sets the number of iterations to calculate the file access validator value (hpm).
     * 
     * @param i iterations (minimum 2048)
     */
    public void setIterations ( int i )
    {
       if ( i < 2048 )
          throw new IllegalArgumentException();
       
       iter = i;
    }
    
    /**
    * Returns the input block stream that is valid to read the remainder of 
    * the file (available only when reading constructor was used).
    * The stream is positioned to the first data element after the file header.
    * 
    * @return PwsBlockInputStream
    */
   public PwsBlockInputStream getBlockStream ()
   {
      return blockStream;
   }

   /** The actual number of iterations set to calculate the file access 
     *  validator value (hpm).
     */ 
    public int getIterations ()
    {
       return iter;
    }
    
    /** A random seed value used for calculating a checksum over the file's data.
     *  (For files-to-be-written only available after <code>save()</code> operation.)
     */ 
    public byte[] getHashSeed ()
    {
       return hseed;
    }

   /** 
    * Returns the hash function verification code actually encountered at the end of a 
    * read-in persistent state of a file.
    * This code serves to verify integrity of user data and is possibly  
    * available after EOF of the input blockstream (returned by <code>verifyPass()</code>) 
    * has been reached; it may, however, not be available at all. 
    *  
    * @return byte[] hmac of length 32 or <b>null</b> if this information is unavailable
    */ 
    public byte[] getReadChecksum ()
    {
       return v3In == null ? null : v3In.getHashMac();
    }
    
    /** 
     * Returns the UUID identifier of the PWS file if it is available.
     * (Note that for files-to-be-read this value is only available after
     * a call to <code>verifyPass()</code> has returned successfull.)
     * 
     * @return file UUID or <b>null</b> if this information is not available
     */
    public UUID getFileID ()
    {
       PwsRawField raw;
       
       raw = hdrFields.getField( FILE_UUID_TYPE );
       return raw == null ? null : new UUID( raw.getData() );
    }
    
    /**
     * Returns a rawfield list containing all available file header fields
     * currently assigned to the PWS file. (Content from a persistent state 
     * (read-in) is only available after <code>verifyPass()</code>.)
     * The returned instance may be used to effectively alter list content. 
     * 
     * @return <code>HeaderFieldList</code>
     */
    public HeaderFieldList getHeaderFields ()
    {
       return hdrFields;
    }
    
    /**
     * Sets the content of a header field. If the field was already present,
     * the previous content is replaced; otherwise a new field is inserted
     * to the header field list. Note: field type 255 is not permitted
     * for a header field.
     * 
     * @param field <code>PwsRawField</code> the new field or field content
     */
    public void setHeaderField ( PwsRawField field )
    {
       hdrFields.setField( field );
    }
    
    /** Returns the specified header field or <b>null</b> if unavailable. */ 
    public PwsRawField getHeaderField ( int type )
    {
       return hdrFields.getField( type );
    }
    
    /**
     * Removes the header field of the given type and returns this
     * field if it was present.
     * 
     * @param type header field type (0..254)
     * @return <code>PwsRawField</code> or <b>null</b>
     * @since 2-1-0
     */
    public PwsRawField removeHeaderField ( int type )
    {
       return hdrFields.removeField( type );
    }
    
	/**
    * Writes the V3 PWS file header part to the given output stream. Constructs 
    * and returns a cipher for the encryption of the remaining parts of the file.
    * 
	* @param output an open <code>OutputStream</code> to which the file is written
    * @param passphrase the user encryption passphrase used for this file
    * @return the <code>PwsCipher</code> with which the remainder of the file 
    *         has to be encrypted
	* 
	* @throws IOException if an IO error occurs
    * @throws NullPointerException on missing param
    */
	public PwsCipher save( OutputStream output, 
                     PwsPassphrase passphrase ) 
                     throws IOException
	{
      PwsCipher  cipher;
      OutputStream out;
      Iterator it;
      byte[] buf;
      
      Log.log( 5, "(PwsFileHeaderV3) save" );
      out = output;
      cipher = update( passphrase );
      writeHmac = new PwsChecksum( hseed );
      
      ensureHeaderDefaults();

      // write the core header part
      out.write( PWS3_FILEID );  // tag
      out.write( salt );
      
      buf = new byte[ 4 ];
      Util.writeIntLittle( iter, buf, 0 );
      out.write( buf );
      
      out.write( hpm );
      out.write( b12 );
      out.write( b34 );
      out.write( iv );
      
      // write the content header fields
      for ( it = hdrFields.iterator(); it.hasNext(); )
      {
         ((PwsRawField)it.next()).writeEncrypted( out, cipher, Global.FILEVERSION_3, writeHmac );
      }
      
      // write field list terminator field
      new PwsRawField( 0xff, null ).writeEncrypted( out, cipher, Global.FILEVERSION_3 );
      
      // log
      Log.log( 5, "(PwsFileHeaderV3) file header saved: " + Util.bytesToHex( salt ));
      return cipher;
	}

    /**
     * Returns the HMAC checksum object to be used for writing the remainder
     * of the file. (Available after <code>save()</code> operation was performed.)
     * 
     * @return <code>PwsChecksum</code>
     */
    public PwsChecksum getWriteHmac ()
    {
       return writeHmac;
    }

   /**
     * Returns the HMAC checksum object to be used for reading the remainder
     * of the file. (Available after <code>verifyPass()</code> operation was performed.)
     * 
     * @return <code>PwsChecksum</code>
     */
    public PwsChecksum getReadHmac ()
    {
       return readHmac;
    }
    
	/**
	 * Prepares the header for saving. Places new random values into all 
     * relevant fields of the file header. Creates and returns the PwsCipher 
     * which is used for encrypting the remainder parts of the file. 
	 * 
	 * @param passphrase the user passphrase to encrypt the database.
    * 
    * @throws NullPointerException if passphrase is undefined
	 */
	private PwsCipher update( PwsPassphrase passphrase )
	{
       PwsCipher internCipher, fileCipher;
       CryptoRandom cra;
       byte[] pkey, fkey;
       
      if ( passphrase == null )
         throw new NullPointerException("passphrase missing");

      isRead = false;

      // create new random values
      cra = Util.getCryptoRand();
      salt = cra.nextBytes( salt.length );
      iv = cra.nextBytes( iv.length );
      fkey = cra.nextBytes( 32 );  // new file cipher key
      hseed = cra.nextBytes( 32 );  // new checksum seed

      // create the passphrase control value
      pkey = makeInternalKey( passphrase, salt, iter );
      hpm = genRandHash( pkey );

      // create internal cipher
      internCipher = new TwofishCipher( pkey );
      
      // encrypt block values (B12, B34)
      b12 = internCipher.encrypt( fkey );
      b34 = internCipher.encrypt( hseed );
      
      isRead = true;
      
      // create the file cipher 
      fileCipher = new TwofishCipher( fkey, iv );
      Util.destroyBytes( fkey );
      Util.destroyBytes( pkey );

      return fileCipher;
	}
   
   /** Verifies whether the file trailing this header can be read with the 
    * passphrase submitted as parameter. In the positive case creates and returns
    * the <code>PwsBlockInputStream</code> which is to be used for reading the 
    * decrypted remainder of the file. This method also prepares the file's header 
    * data fields (e.g. preferences, uuid, options, etc.) to become retrieveable 
    * through this header. 
    * 
    * @param passphrase PwsPassphrase a candidate file access key 
    * @return a <code>PwsCipher</code> value not <b>null</b> if and only if the 
    *         file of this header is accessible (can be decrypted) with the 
    *         specified passphrase
    * 
    * @throws NullPointerException if passphrase is undefined
    * @throws IllegalStateException if the header is not read from a file
    *         or already has been verified before
    */ 
   public PwsBlockInputStream verifyPass ( PwsPassphrase passphrase ) throws IOException
   {
      PwsCipher internCipher, fileCipher;
      PwsRawField raw;
      byte[] fkey, pkey, randHash, block;
      
      if ( passphrase == null )
         throw new NullPointerException("passphrase missing");
      if ( !isRead )
         throw new IllegalStateException("header not initialized");
      if ( isVerified )
         throw new IllegalStateException("duplicate header verification");

      // verify correct passphrase
      // create the passphrase control value
      pkey = makeInternalKey( passphrase, salt, iter );
      randHash = genRandHash( pkey );

      // if we have the correct passphrase
      if ( Util.equalArrays( randHash, hpm ) )
      {
         // create internal cipher
         internCipher = new TwofishCipher( pkey );
       
         // decrypt block values
         fkey = internCipher.decrypt( b12 );
         hseed = internCipher.decrypt( b34 );

         // instantiate read-HMAC  
         readHmac = new PwsChecksum( hseed );
         
         // create file cipher
         fileCipher = new TwofishCipher( fkey, iv );
         Util.destroyBytes( fkey );
         
         // read content header fields
         v3In = new V3_InputStream( input );
         blockStream = new BlockInputStream( v3In, fileCipher );
         while ( true )
         {
            block = blockStream.peekBlock();

            // quit reading if end-block appears
            if ( block[4] == (byte)0xff )
            {
               blockStream.readBlock();
               break;
            }
            
            // else read a rawfield
            raw = new PwsRawField( blockStream, Global.FILEVERSION_3 );
            Log.log( 5, "** read HEADER FIELD: t=" + raw.getType() + ", c=" + Util.bytesToHex( raw.getData() ));
            Log.log( 5, "                            " + Util.printableString( raw.getString( "UTF-8" ) ));
            setHeaderField( raw );
            readHmac.update( raw );
         }
         
         isVerified = true;
         blockStream.resetCounter();
         return blockStream;
      }  
      return null;
   }

   /** Creates a PKEY from its given parameters. */
   private static byte[] makeInternalKey ( PwsPassphrase passphrase, byte[] random, int iterations )
   {
      SHA256 sha = new SHA256();
      byte[] key, x;
      int i;
      
      key = passphrase.getBytes( null );

      // calculate foot value (integrating salt) 
      sha.update( key );
      Util.destroyBytes( key );
      sha.update( random );
      x = sha.digest();
      
      // perform iterations
      for ( i = 0; i < iterations; i++ )
      {
         sha.reset();
         sha.update( x );
         x = sha.digest();
      }
      
      return x;
   }

   private static byte[] genRandHash ( byte[] pkey )
   {
      SHA256 sha = new SHA256();
      byte[] result;
      
      sha.update( pkey );
      result = sha.digest();
      
      Log.debug( 10, "(PwsFileHeaderV3) producing a key validator hash =" + Util.bytesToHex( result ) );
      return result;
   }
   
   /** Returns a cryptographic hash value for a random salt block and a passphrase.
    *  This follows a special procedure defined for PasswordSafe V3 files.
    * 
    *  @return cryptographic hash value on the parameters
    */
   public static byte[] genRandHash ( PwsPassphrase passphrase, byte[] random, int iterations )
   {
      byte[] pkey;
      
      pkey = makeInternalKey( passphrase, random, iterations );
      return genRandHash( pkey );
   }
}
