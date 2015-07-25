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

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;

import org.jpws.pwslib.crypto.BlowfishCipher;
import org.jpws.pwslib.crypto.CryptoRandom;
import org.jpws.pwslib.crypto.PwsCipher;
import org.jpws.pwslib.crypto.SHA1;
import org.jpws.pwslib.exception.WrongFileVersionException;
import org.jpws.pwslib.global.Global;
import org.jpws.pwslib.global.Log;
import org.jpws.pwslib.global.Util;


/**
 * This class represents the header fields of a <b>PasswordSafe V1</b> database
 * (persistent state) and allows to obtain objects enabling to read the
 * remainder of the file in a decrypted fashion or to save the header to a new 
 * persistent state. 
 *   
 * <p>The original format definition of V1 files is available under document name: ??   
 * 
 * @author Wolfgang Keller
 * @since 2-0-0
 */
class PwsFileHeaderV1
{
   /** Internal constant for database version identification. */
   private static final String V2_IDENTTEXT = " !!!Version 2 File Format!!! Please upgrade to PasswordSafe 2.0 or later";
   private static final int MAX_READ_AHEAD = 32000;


	private byte [] randStuff	= new byte[  8 ];
	private byte [] randHash	= new byte[ 20 ];
	private byte [] salt	    = new byte[ 20 ];
	private byte [] ipThing		= new byte[  8 ];
    private boolean isRead;

    private BufferedInputStream input;
    private BlockInputStream    blockStream; 
    
	/**
	 * Writing constructor. Creates an empty file header usable to create a new PWS database
     * (persistent state).
	 */
	PwsFileHeaderV1()
	{
	}

	/**
	 * Reading constructor. Creates a value-assigned file header by reading the data 
    * from the parameter inputstream which contains the persistent state of a file. 
    * (This is the mandatory constructor to perform passphrase verification on a header.) 
	 * 
	 * @param input <code>BufferedInputStream</code> positioned at the beginning of a PWS file
	 * @throws IOException  if an error occurs during reading
	 */
	public PwsFileHeaderV1( BufferedInputStream input )  throws IOException
	{
       DataInputStream in;

       this.input = new BufferedInputStream( input );
       in = new DataInputStream( input );

       // read the core header values
       in.readFully( randStuff );
       in.readFully( randHash );
       in.readFully( salt );
       in.readFully( ipThing );

       // mark internal buffered input stream to first data element 
       this.input.mark( MAX_READ_AHEAD );
       isRead = true;
       Log.log( 5, "(PwsFileHeaderV1) file header read: " + Util.bytesToHex( randStuff, 0, randStuff.length ));
	}

	/**
	 * Writes the header part to the file. Constructs and returns a cipher for 
     * the encryption of the succeeding parts of the file.
	 * 
	 * @param output an open OutputStream to which the file is written
     * @param passphrase the file access passphrase
     *  
     * @return the <code>PwsCipher</code> with which the remainder of the file 
     *         has to be encrypted
	 * 
	 * @throws IOException if an IO error occurs
     * @throws NullPointerException on any missing parameter
	 */
	public PwsCipher save( OutputStream output, 
                     PwsPassphrase passphrase ) 
                     throws IOException
	{
      PwsCipher  cipher;
      DataOutputStream out;
      
      if ( output == null )
         throw new NullPointerException();
      
      cipher = update( passphrase );
      out = new DataOutputStream( output );

      // write the core header part
      out.write( randStuff );
      out.write( randHash );
      out.write( salt );
      out.write( ipThing );

      // log
      Log.log( 5, "(PwsFileHeaderV1) file header saved: " + Util.bytesToHex( randStuff, 0, randStuff.length ));
      return cipher;
	}

	/**
	 * Prepares the header for saving. Places new random values into all fields
    * of the file header. Creates and returns the PwsCipher which is used for
    * encrypting the remainder of the file. 
	 * 
	 * @param passphrase the passphrase to be used to encrypt the database.
    * 
    * @throws NullPointerException if passphrase is undefined
	 */
	private PwsCipher update( PwsPassphrase passphrase )
	{
       CryptoRandom cra;
       
      if ( passphrase == null )
         throw new NullPointerException("passphrase missing");

      // create the passphrase control value
      cra = Util.getCryptoRand();
      randStuff = cra.nextBytes( randStuff.length );
      randHash	= PwsFileHeaderV1.genRandHash( passphrase, randStuff );

      // create the file cipher (and elements)
      salt = cra.nextBytes( salt.length );
      ipThing = cra.nextBytes( ipThing.length );
      isRead = true;

      return makeFileCipher( passphrase );
	}
   
   /** Verifies whether the file trailing this header can be read with the 
    * passphrase submitted as parameter. In the positive case returns
    * the <code>PwsBlockInputStream</code> which is to be used for reading the
    * decrypted remainder of the file. This method also verifies the correct 
    * file version (V1).
    * 
    * @param passphrase PwsPassphrase a candidate file access key 
    * @return <code>PwsBlockInputStream</code> not <b>null</b> if and only if the 
    *         file of this header is accessible with the 
    *         specified passphrase and is a version V1 file
    * 
    * @throws NullPointerException if passphrase is undefined
    * @throws IllegalStateException if the header is unprepared (not read from file)
    * @throws WrongFileVersionException if a V2 file format was encountered
    */ 
   public PwsBlockInputStream verifyPass ( PwsPassphrase passphrase ) 
      throws IOException, WrongFileVersionException
   {
      PwsCipher cipher;
      PwsRawField raw;
      String idText;
      byte[] result;
      
      if ( passphrase == null )
         throw new NullPointerException("passphrase missing");
      if ( !isRead )
         throw new IllegalStateException("header not initialized");

      // verify correct passphrase
      result = PwsFileHeaderV1.genRandHash( passphrase, randStuff );
      if ( Util.equalArrays( randHash, result ) )
      {
         // we have the correct passphrase here
         cipher = makeFileCipher( passphrase );
       
         // now try to read first field to discriminate V2 files
         input.reset();
         blockStream = new BlockInputStream( input, cipher );
         try {
            // read possible version ID field
            raw = new PwsRawField( blockStream, Global.FILEVERSION_1 ); 
            idText = raw.getString( "US-ASCII" );
         
            // look for V2 file version  
            if ( idText.equals( V2_IDENTTEXT ) )
            {
               throw new WrongFileVersionException();
            }
         }
         catch ( EOFException e )
         {
            // nothing because we likely encountered an empty V1 file 
         }
         finally 
         {
            // need to reconstruct CBC cipher and blockstream after data reset
            cipher = makeFileCipher( passphrase );
            input.reset();
            blockStream = new BlockInputStream( input, cipher );
         }

         // upon verified V1 file
         input.mark( 0 );  // avoid further buffering in this stream
         blockStream.resetCounter();
         return blockStream;
      }

      // wrong passphrase here
      return null;
   }
   
   /**
    * Returns the input block stream that is valid to read the remainder of 
    * the file (available only when reading constructor was used).
    * The stream is positioned to the first data element after the file header.
    * 
    * @return BufferedInputStream
    */
   public PwsBlockInputStream getBlockStream ()
   {
      return blockStream;
   }

   /** Creates a file encryption/decryption cipher from a passphrase
    *  and the stored header values. This will return a Blowfish 
    *  cipher in CBC mode; it should be used only in one direction
    *  (encryption or decryption).
    * 
    * @param passphrase
    * @return PwsCipher the file cipher
    * 
    * @throws NullPointerException if passphrase is undefined
    * @throws IllegalStateException if the header is unprepared (not read from file)
    */
   private PwsCipher makeFileCipher ( PwsPassphrase passphrase )
   {
      SHA1 sha = new SHA1();
      PwsCipher cipher;
      byte[] pass;

      if ( passphrase == null )
         throw new NullPointerException("passphrase missing");
      if ( !isRead )
         throw new IllegalStateException("header not initialized");
      
      pass = passphrase.getBytes( PwsFileFactory.DEFAULT_CHARSET );
      sha.update( pass );
      Util.destroyBytes( pass );
      sha.update( salt );
      sha.finalize();
      
      cipher = new BlowfishCipher( sha.getDigest(), ipThing );
//      Log.debug( 10, "(PwsFileHeaderV2.makeFileCipher) digest = " + Util.bytesToHex( sha.getDigest() ));
//      Log.debug( 10, "(PwsFileHeaderV2.makeFileCipher) IP = " + Util.bytesToHex( ipThing ));

      Log.log( 7, "(PwsFileHeaderV2) file cipher created for " + passphrase );
      return cipher;
   }

   /** Returns a cryptographic hash value for a given data block and a passphrase.
    *  This follows a special procedure defined for PWS V1 files.
    * 
    *  @return cryptographic hash value on the parameters
    */
   public static byte[] genRandHash ( PwsPassphrase passphrase, byte[] randStuff )
   {
      PwsCipher ciph;
      SHA1 sha = new SHA1();
      byte[] pass, rnd, tempSalt, buf;
      int i;
      
      // create tempSalt as encryption key for randomStuff
      pass = passphrase.getBytes( PwsFileFactory.DEFAULT_CHARSET );
      rnd = Util.arraycopy( randStuff, 10 );
      sha.update( rnd );
      sha.update( pass );
      Util.destroyBytes( pass );
      sha.finalize();
      tempSalt = sha.getDigest();
      Log.debug( 10, "(PwsFileHeaderV2.genRandHash) digest = " + Util.bytesToHex( tempSalt ));
      
      // create RandHash
      ciph = new BlowfishCipher( tempSalt );
      rnd = Util.arraycopy( randStuff, 8 ); 
      Log.debug( 10, "(PwsFileHeaderV2.genRandHash) rnd = " + Util.bytesToHex( rnd ));
   
      for ( i = 0; i < 1000; i++ )
         rnd = ciph.encrypt( rnd );
      Log.debug( 10, "(PwsFileHeaderV2.genRandHash) rnd encrypted = " + Util.bytesToHex( rnd ));
      
      buf = Util.arraycopy( rnd, 10 );
      sha.clearContext();
      sha.update( buf );
      sha.finalize();
   
      Log.debug( 10, "(PwsFileHeaderV2) producing a randHash =" + Util.bytesToHex(sha.getDigest())
            + " for randStuff =" + Util.bytesToHex(randStuff) );
      return sha.getDigest();
   }
}
