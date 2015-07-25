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
 * This class represents the header fields of a <b>PasswordSafe V2</b> database
 * (persistent state) and allows to obtain objects enabling to read the
 * remainder of the file in a decrypted fashion or to save the header to a new 
 * persistent state. 
 *   
 * <p>The original format definition of V2 files is available under document name: "?"
 * in the document folder of the developer download package.   
 * 
 * @author Wolfgang Keller
 * @since 2-0-0
 */
class PwsFileHeaderV2
{
   /** Internal constant for database version identification. (9 blocks field data) */
   private static final String VERSION_IDENTTEXT = " !!!Version 2 File Format!!! Please upgrade to PasswordSafe 2.0 or later";


	private byte [] randStuff	= new byte[  8 ];
	private byte [] randHash	= new byte[ 20 ];
	private byte [] salt	    = new byte[ 20 ];
	private byte [] ipThing		= new byte[  8 ];
    private boolean isRead;

    private InputStream input;
    private BlockInputStream    blockStream; 
    private String  options     = "";

	/**
	 * Creates an empty file header. This may be used to create a new PWS file.
	 */
	PwsFileHeaderV2()
	{
	}

	/**
	 * Constructs the PWS file header by reading the header data 
     * from the parameter inputstream. (This is the mandatory usage to
     * perform passphrase verification on a header.)
	 * 
	 * @param input java.io.InputStream, placed at the beginning of a PWS file
	 * @throws IOException if an IO-error occurs 
	 */
	public PwsFileHeaderV2( InputStream input )  throws IOException
	{
       DataInputStream in;

       this.input = input;
       in = new DataInputStream( input );

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
    * @return <code>PwsBlockInputStream</code> or <b>null</b> if object is unverified
    */
   public PwsBlockInputStream getInputBlockStream ()
   {
      return blockStream;
   }

   /** 
     * Returns the options string saved for the PWS file.
     * (This is only reflecting a file state after <code>verifyPass()</code>
     * was performed with positive result.)
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
       if ( s == null )
          s = "";
       options = s;
    }
    
	/**
	 * Writes the header part to the file. Constructs and returns the cipher to 
	 * encrypt the remaining parts of the file.
     * (<p>NOTE: As of PWSLIB-2 the header part encompasses the V2 administration
     * block, which denotes file version marker and the option string.)   
	 * 
	 * @param output an open OutputStream to which the file is written
     *        (placed at file start) 
     * @param passphrase the user encryption passphrase used for this file
     * @param options optional user options text, may be <b>null</b>

     * @return the <code>PwsCipher</code> with which the remainder of the file 
     *         has to be encrypted
	 * 
     * @throws NullPointerException if <code>output</code> or <code>passphrase</code>
     *         are undefined
	 * @throws IOException if an IO error occurs
     * @throws IllegalArgumentException on missing param
	 */
	public PwsCipher save( OutputStream output, 
                     PwsPassphrase passphrase,
                     String options ) 
                     throws IOException
	{
       
      PwsCipher  cipher;
      DataOutputStream out;
      
      if ( output == null )
         throw new NullPointerException();
      
      cipher = update( passphrase );
      out = new DataOutputStream( output );
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
	 * @param passphrase the user's file access passphrase
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
      randHash	= PwsFileHeaderV2.genRandHash( passphrase, randStuff );

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
    * file version (V2). 
    * 
    * @param passphrase PwsPassphrase as candidate file access key
    * @return <code>PwsBlockInputStream</code> value not <b>null</b> if and only if the 
    *         file is accessible (can be decrypted) with the specified passphrase 
    *         and is a version V2 file
    * 
    * @throws NullPointerException if passphrase is undefined
    * @throws IllegalStateException if the header is unprepared (not read from file)
    * @throws WrongFileVersionException if a file version other than V2 was encountered
    */ 
   public PwsBlockInputStream verifyPass ( PwsPassphrase passphrase ) throws IOException, WrongFileVersionException
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
      result = PwsFileHeaderV2.genRandHash( passphrase, randStuff );
      if ( Util.equalArrays( randHash, result ) )
      try {
         // we have the correct passphrase here
         cipher = makeFileCipher( passphrase );
         blockStream = new BlockInputStream( input, cipher );
       
         // now reading the V2 administration block
         raw = new PwsRawField( blockStream, Global.FILEVERSION_2 );  // version ID field
         idText = raw.getString( "US-ASCII" );
         
         // verify correct file version (V2)  
         if ( idText.equals( VERSION_IDENTTEXT ) )
         {
            // read rest of Format Description Block
            raw = new PwsRawField( blockStream, Global.FILEVERSION_2 ); // Password
            Log.debug( 10, "PWS file format ID = " + raw.getString("US-ASCII") );
            
            raw = new PwsRawField( blockStream, Global.FILEVERSION_2 ); // Notes
            options = raw.getString( "ISO-8859-1" );

            blockStream.resetCounter();
            return blockStream;
         }
         else
            throw new WrongFileVersionException();
      }
      catch ( EOFException e )
      {
         // nothing because we likely encountered an empty V1 file 
      }
      return null;
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

   /** Returns a cryptographic hash value for a specimen data block and a passphrase.
    *  This follows a special procedure defined for PasswordSafe files.
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
