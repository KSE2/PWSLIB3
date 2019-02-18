/*
 *  File: PwsFileHeaderV1.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 07.08.2005
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

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
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
 * This class represents the technical header data of a <b>PasswordSafe V1</b> 
 * database (persistent state) and allows to obtain objects enabling to read the
 * remainder of the file decrypted or to save the header to a new 
 * persistent state. 
 * <p>V1 is a format based on SHA1 and the  Blowfish cipher; it does not supply 
 * generic header data for the user. The use of this format is historical and 
 * deprecated for productive data files!
 *   
 * <p>The original format definition as of the Password Safe project is 
 * available under document name "formatV1.txt" in the document folder of the 
 * developer package of this library.      
 * 
 * @author Wolfgang Keller
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
	 * Writing constructor. Creates an empty file header usable to create 
	 * a new PWS database (persistent state).
	 */
	PwsFileHeaderV1 ()
	{}

	/**
	 * Reading constructor. Creates a file header by reading data from the 
	 * parameter input stream which contains the persistent state of a PWS file. 
    * (This is the mandatory constructor to perform passphrase verification on 
    * a file.) 
	 * 
	 * @param input <code>BufferedInputStream</code> positioned at the beginning
	 *              of a PWS file
	 * @throws IOException  if an error occurs during reading
	 * @throws NullPointerException if parameter is <b>null</b>
	 */
	public PwsFileHeaderV1( InputStream input )  throws IOException
	{
       this.input = new BufferedInputStream(input);
       DataInputStream in = new DataInputStream( input );

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
     * the encryption of the following parts of the file.
	 * 
	 * @param output OutputStream, an open stream to which the file is written
     * @param passphrase PwsPassphrase, the file access passphrase
     * @return the <code>PwsCipher</code> with which the remainder of the file 
     *         is to be encrypted
	 * @throws IOException if an IO error occurs
     * @throws NullPointerException on any missing parameter
	 */
	public PwsCipher save( OutputStream output, 
                           PwsPassphrase passphrase ) throws IOException
	{
      if ( output == null )
         throw new NullPointerException();
      
      PwsCipher cipher = update( passphrase );
      DataOutputStream out = new DataOutputStream( output );

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
	* @param passphrase PwsPassphrase, the passphrase to be used to encrypt 
	*                   the database.
    * 
    * @throws NullPointerException if passphrase is null
	*/
	private PwsCipher update( PwsPassphrase passphrase )
	{
      if ( passphrase == null )
         throw new NullPointerException("passphrase missing");

      // create the passphrase control value
      CryptoRandom cra = Util.getCryptoRand();
      randStuff = cra.nextBytes( randStuff.length );
      randHash	= PwsFileHeaderV1.genRandHash( passphrase, randStuff );

      // create the file cipher (and elements)
      salt = cra.nextBytes( salt.length );
      ipThing = cra.nextBytes( ipThing.length );
      isRead = true;

      return makeFileCipher( passphrase );
	}
   
   /** Verifies whether the file trailing this header can be read with the 
    * given passphrase. If yes, this returns the <code>PwsBlockInputStream</code> 
    * which is to be used for reading the decrypted remainder of the file. 
    * This method also verifies the correct file version V1.
    * 
    * @param passphrase PwsPassphrase, a candidate file access key 
    * @return <code>PwsBlockInputStream</code> not <b>null</b> if and only if 
    *         the file of this header is accessible with the 
    *         specified passphrase and is a version V1 file
    * @throws NullPointerException if passphrase is null
    * @throws IllegalStateException if the header is unprepared 
    *         (not read from file)
    * @throws WrongFileVersionException if a V2 file format was encountered
    */ 
   public PwsBlockInputStream verifyPass ( PwsPassphrase passphrase ) 
      throws IOException, WrongFileVersionException
   {
      if ( passphrase == null )
         throw new NullPointerException("passphrase missing");
      if ( !isRead )
         throw new IllegalStateException("header not initialized");
      if ( blockStream != null )
          throw new IllegalStateException("cipher already verified!");

      // verify correct passphrase
      byte[] result = PwsFileHeaderV1.genRandHash( passphrase, randStuff );
      if ( Util.equalArrays( randHash, result ) ) {
    	  
         // we have the correct passphrase here
    	  PwsCipher cipher = makeFileCipher( passphrase );
       
         // now try to read first field to discriminate V2 files
         input.reset();
         blockStream = new BlockInputStream( input, cipher, Global.BLOCK_BUFFER_FACTOR );
         try {
            // read possible version ID field
        	PwsRawField raw = new PwsRawField( blockStream, Global.FILEVERSION_1 ); 
            String idText = raw.getString( "US-ASCII" );
         
            // look for V2 file version  
            if ( idText.equals( V2_IDENTTEXT ) ) {
               throw new WrongFileVersionException();
            }

         } catch ( EOFException e ) {
            // nothing because we likely encountered an empty V1 file 

         } finally {
            // need to reconstruct CBC cipher and blockstream after data reset
            cipher = makeFileCipher( passphrase );
            input.reset();
            blockStream = new BlockInputStream( input, cipher, Global.BLOCK_BUFFER_FACTOR );
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
    * the file. This is available only when the reading constructor was used
    * and <code>verifyPass()</code> returned with success.
    * The stream is positioned to the first data element after the file header.
    * 
    * @return <code>PwsBlockInputStream</code> or null
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
    * @param passphrase <code>PwsPassphrase</code>
    * @return PwsCipher the file cipher
    * @throws NullPointerException if passphrase is null
    * @throws IllegalStateException if the header is unprepared 
    *         (not read from file)
    */
   private PwsCipher makeFileCipher ( PwsPassphrase passphrase )
   {
      if ( passphrase == null )
         throw new NullPointerException("passphrase missing");
      if ( !isRead )
         throw new IllegalStateException("header not initialized");
      
      SHA1 sha = new SHA1();
      byte[] pass = passphrase.getBytes( PwsFileFactory.DEFAULT_CHARSET );
      sha.update( pass );
      Util.destroyBytes( pass );
      sha.update( salt );
      sha.finalize();
      
      PwsCipher cipher = new BlowfishCipher( sha.getDigest(), ipThing );
//      Log.debug( 10, "(PwsFileHeaderV2.makeFileCipher) digest = " + Util.bytesToHex( sha.getDigest() ));
//      Log.debug( 10, "(PwsFileHeaderV2.makeFileCipher) IP = " + Util.bytesToHex( ipThing ));

      Log.log( 7, "(PwsFileHeaderV2) file cipher created for " + passphrase );
      return cipher;
   }

   /** Returns a cryptographic hash value for a given data block and a 
    * passphrase. This follows a special procedure defined for PWS V1 files.
    * 
    *  @param passphrase PwsPassphrase access key 
    *  @param randStuff byte[] random data block (min length 10)
    *  @return cryptographic hash value on the parameters
    */
   public static byte[] genRandHash ( PwsPassphrase passphrase, byte[] randStuff )
   {
      byte[] pass, rnd, tempSalt, buf;
      
      // create tempSalt as encryption key for randomStuff
      SHA1 sha = new SHA1();
      pass = passphrase.getBytes( PwsFileFactory.DEFAULT_CHARSET );
      rnd = Util.arraycopy( randStuff, 10 );
      sha.update( rnd );
      sha.update( pass );
      Util.destroyBytes( pass );
      sha.finalize();
      tempSalt = sha.getDigest();
      Log.debug( 10, "(PwsFileHeaderV2.genRandHash) digest = " + Util.bytesToHex( tempSalt ));
      
      // create RandHash
      PwsCipher ciph = new BlowfishCipher( tempSalt );
      rnd = Util.arraycopy( randStuff, 8 ); 
      Log.debug( 10, "(PwsFileHeaderV2.genRandHash) rnd = " + Util.bytesToHex( rnd ));
   
      for ( int i = 0; i < 1000; i++ ) {
         rnd = ciph.encrypt( rnd );
      }
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
