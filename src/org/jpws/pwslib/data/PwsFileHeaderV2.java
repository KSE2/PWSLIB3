/*
 *  File: PwsFileHeaderV2.java
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
 * This class represents the technical header data of a <b>PasswordSafe V2</b> 
 * database (persistent state) and allows to obtain objects enabling to read 
 * and decrypt the remainder of the file or to save freshly initialised header 
 * data to a new persistent state. V2 is a format based on SHA1 and the 
 * Blowfish cipher; it does not supply generic header data for the user.
 * The use of this format is historical and deprecated for productive data
 * files!
 *   
 * <p>The original format definition as of the Password Safe project is 
 * available under document name "formatV2.txt" in the document folder of the 
 * developer package of this library.   
 * 
 * @author Wolfgang Keller
 */
class PwsFileHeaderV2
{
   /** Internal constant for database version identification. 
    * (9 blocks field data) 
    */
   private static final String VERSION_IDENTTEXT = " !!!Version 2 File Format!!! Please upgrade to PasswordSafe 2.0 or later";


	private byte [] randStuff	= new byte[  8 ];
	private byte [] randHash	= new byte[ 20 ];
	private byte [] salt	    = new byte[ 20 ];
	private byte [] ipThing		= new byte[  8 ];
    private boolean isRead;

    private InputStream 		input;
    private BlockInputStream    blockStream; 
    private String  			options = "";

	/**
	 * Creates an empty file header. This may be used to create a new PWS file.
	 */
	PwsFileHeaderV2()
	{}

	/**
	 * Constructs the PWS file header by reading the header data from the 
	 * parameter input stream. (This is the mandatory usage to perform 
	 * passphrase verification on a header.)
	 * 
	 * @param input java.io.InputStream, placed at the beginning of a PWS file
	 * @throws IOException if an IO-error occurs 
	 */
	public PwsFileHeaderV2( InputStream input )  throws IOException
	{
       this.input = input;
       DataInputStream in = new DataInputStream( input );

       // read the core header values
       in.readFully( randStuff );
       in.readFully( randHash );
       in.readFully( salt );
       in.readFully( ipThing );
       isRead = true;
       Log.log( 5, "(PwsFileHeaderV2) file header read: " + Util.bytesToHex( randStuff, 0, randStuff.length ));
	}

	/**
    * Returns the input block stream that is valid to read the remainder of 
    * the file (available only when reading constructor was used and after <code>
    * verifyPass()</code> was performed with positive result).
    * The stream is positioned to the first data element after the file header.
    * (NOTE: This is the same object as returned by <code>verifyPass()</code>.)
    * 
    * @return <code>PwsBlockInputStream</code> or <b>null</b> if object is 
    *         unverified
    */
   public PwsBlockInputStream getInputBlockStream ()
   {
      return blockStream;
   }

   /** 
     * Returns the options string saved for the PWS file.
     * (This is only reflecting a file state after <code>verifyPass()</code>
     * was performed with success.)
     * 
     * @return String, text, may be empty
     */
    public String getOptions ()
    {
       return options;
    }
    
    /**
     * Sets the options string to be saved for the PWS file.
     * 
     * @param s String, options text (<b>null</b> equivalent to empty string)
     */
    public void setOptions ( String s )
    {
       if ( s == null ) {
          s = "";
       }
       options = s;
    }
    
	/**
	 * Writes the header part to the file. Constructs and returns the cipher to 
	 * encrypt the remaining parts of the file.
     * (<p>NOTE: As of PWSLIB-2 the header part encompasses the V2 administration
     * block, which denotes file version marker and the option string.)   
	 * 
	 * @param output OutputStream, an open stream to which the file is written
     *               (positioned at file start) 
     * @param passphrase PwsPassphrase, the user encryption passphrase used for 
     *               this file
     * @param options String, optional user options text, may be <b>null</b>
     * @return <code>PwsCipher</code> used to encrypted the remainder of the
     *         file 
     * @throws NullPointerException if <code>output</code> or 
     *         <code>passphrase</code> are <b>null</b>
	 * @throws IOException if an IO error occurs
     * @throws IllegalArgumentException on missing parameter
	 */
	public PwsCipher save( OutputStream output, 
                           PwsPassphrase passphrase,
                           String options )  throws IOException
	{
      if ( output == null )
         throw new NullPointerException();
      
      PwsCipher cipher = update( passphrase );
      DataOutputStream out = new DataOutputStream( output );
      setOptions( options );

      // write the core header part
      out.write( randStuff );
      out.write( randHash );
      out.write( salt );
      out.write( ipThing );

      // write the version description block (V2 administration block)
      new PwsRawField( 0, VERSION_IDENTTEXT.getBytes("ASCII") ).writeEncrypted( output, cipher, Global.FILEVERSION_2 );
      new PwsRawField( PwsFileFactory.PASSWORDTYPE, "2.0".getBytes("ASCII") ).writeEncrypted( output, cipher, Global.FILEVERSION_2 );
      new PwsRawField( PwsFileFactory.NOTESTYPE, this.options.getBytes("ISO-8859-1")).writeEncrypted( output, cipher, Global.FILEVERSION_2 );
      
      // log
      Log.log( 5, "(PwsFileHeaderV2) file header saved: " + Util.bytesToHex( randStuff, 0, randStuff.length ));
      return cipher;
	}

	/**
	 * Prepares the header for saving. Places new random values into all fields
     * of the file header. Creates and returns the cipher which is used to
     * encrypt the remainder of the file. 
	 * 
	 * @param passphrase PwsPassphrase, the user's file access passphrase
     * @throws NullPointerException if <code>passphrase</code> is null
	 */
	private PwsCipher update( PwsPassphrase passphrase )
	{
      if ( passphrase == null )
         throw new NullPointerException("passphrase missing");

      // create the passphrase control value
      CryptoRandom cra = Util.getCryptoRand();
      randStuff = cra.nextBytes( randStuff.length );
      randHash	= PwsFileHeaderV2.genRandHash( passphrase, randStuff );

      // create the file cipher (and elements)
      salt = cra.nextBytes( salt.length );
      ipThing = cra.nextBytes( ipThing.length );
      isRead = true;

      return makeFileCipher( passphrase );
	}
   
   /** Verifies whether the file trailing this header can be read with the 
    * passphrase submitted as parameter. If yes, this returns
    * the <code>PwsBlockInputStream</code> which is to be used for reading the 
    * decrypted remainder of the file. This method also verifies the correct 
    * file version (V2). 
    * 
    * @param passphrase PwsPassphrase, candidate file access key
    * @return <code>PwsBlockInputStream</code> value not <b>null</b> if and only
    *         if the file is accessible (can be decrypted) with the specified 
    *         passphrase and is a version V2 file
    * @throws NullPointerException if passphrase is null
    * @throws IllegalStateException if the header is unprepared 
    *         (not read from file)
    * @throws WrongFileVersionException if a file version other than V2 was 
    *         encountered
    */ 
   public PwsBlockInputStream verifyPass ( PwsPassphrase passphrase ) 
		       throws IOException, WrongFileVersionException
   {
      if ( passphrase == null )
         throw new NullPointerException("passphrase missing");
      if ( !isRead )
         throw new IllegalStateException("header not initialized");

      // verify correct passphrase
      byte[] result = PwsFileHeaderV2.genRandHash( passphrase, randStuff );
      if ( Util.equalArrays( randHash, result ) )
      try {
         // we have the correct passphrase here
    	 PwsCipher cipher = makeFileCipher( passphrase );
         blockStream = new BlockInputStream( input, cipher );
       
         // now reading the V2 administration block
         // read the version ID field
         PwsRawField raw = new PwsRawField( blockStream, Global.FILEVERSION_2 );
         String idText = raw.getString( "US-ASCII" );
         
         // verify correct file version (V2)  
         if ( idText.equals( VERSION_IDENTTEXT ) ) {
            // read rest of Format Description Block
            raw = new PwsRawField( blockStream, Global.FILEVERSION_2 ); // Password
            Log.debug( 10, "PWS file format ID = " + raw.getString("US-ASCII") );
            
            raw = new PwsRawField( blockStream, Global.FILEVERSION_2 ); // Notes
            options = raw.getString( "ISO-8859-1" );

            blockStream.resetCounter();
            return blockStream;

         } else {
            throw new WrongFileVersionException();
         }
         
      } catch ( EOFException e ) {
         // nothing because we likely encountered an empty V1 file 
      }
      return null;
   }

   /** Creates a file encryption/decryption cipher from a passphrase and the 
    *  stored header values. This will return a Blowfish cipher in CBC mode; 
    *  it should be used only in one direction (encryption or decryption).
    * 
    * @param passphrase PwsPassphrase
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
    * passphrase. This follows a special procedure defined for PasswordSafe 
    * files.
    * 
    * @return byte[] cryptographic hash value on the parameters
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
