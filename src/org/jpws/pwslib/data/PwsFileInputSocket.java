/*
 *  File: PwsFileInputSocket.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 20.08.2006
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
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

import org.jpws.pwslib.crypto.PwsCipher;
import org.jpws.pwslib.exception.UnsupportedFileVersionException;
import org.jpws.pwslib.exception.WrongFileVersionException;
import org.jpws.pwslib.global.Global;
import org.jpws.pwslib.global.UUID;


/**
 *  PwsFileInputSocket organises data input from an ordinary 
 *  underlying data stream in order to read a persistent state of a
 *  PWS file and make its data content available to the user in a decrypted
 *  and convenient form. This takes care of decryption and unpacking 
 *  depending on the different PWS file format versions in a way that lets 
 *  the user ignore these differences. 
 *  
 *  <p>One instance of this socket can be used to obtain a single 
 *  instance of either the block-stream or the raw-field reader. Before this,
 *  the socket must be opened through the <code>attemptOpen()</code> method,
 *  which can be performed repeatedly until the correct key (and file version) 
 *  have been matched. An instance can be opened only once.   
 *  
 *  <p>NOTE: It is recommended that the data source input stream contains
 *  only the persistent state of a PWS file. For V3 files trailing extra data
 *  may be present in the stream but may get partly lost for subsequent users of
 *  the same input stream. 
 *  
 *  @see org.jpws.pwslib.data.PwsRawFieldReader
 *  @see org.jpws.pwslib.data.PwsBlockInputStream
 */

public class PwsFileInputSocket {
	
   private static final int MAX_READ_AHEAD = 32000;

   private boolean isOpen, isConsumed;
   private int fversion;
   private String options = "";  // options from file header
   
   private BufferedInputStream in;
   private PwsBlockInputStream blockStream;
   private PwsBlockInputStream userStream;
   private HeaderFieldList headerFields;
   private PwsFileHeaderV3 headerV3;
   private PwsChecksum hmac;
   private int cipherKeyLength;
   
   

 /**
 * Creates a file input socket with the parameter input stream
 * as data source. The data stream comprises the entire encrypted file.
 * Encryption key length is 256 bits (maximum).
 * 
 * @param input <code>InputStream</code>
 */   
public PwsFileInputSocket ( InputStream input ) {
	this(input, 256);
}


/**
 * Creates a file input socket with the parameter input stream
 * as data source and the given encryption quality value. 
 * The data stream comprises the entire encrypted file. The quality is a
 * machine level key length value in bits, one of (256, 192, 128, 64). 
 * Encryption quality grows with the value.
 * 
 * @param input <code>InputStream</code>
 * @param keyLength int encryption quality marker in bits, (256, 192, 128, 64)
 */   
public PwsFileInputSocket ( InputStream input, int keyLength ) {
   Objects.requireNonNull(input, "input is null");	
   setKeySecurity(keyLength);
   
   in = (input instanceof BufferedInputStream) ? 
        (BufferedInputStream)input : new BufferedInputStream( input );
   in.mark( MAX_READ_AHEAD );
}

/**
 * Attempts to open this socket by trying a key on a 
 * PWS file of any format which is read from the supplied input stream 
 * starting at its current position. Repeated calls to this method (open
 * attempts) are possible as long as previous calls have all
 * rendered negative. This method tries out all known PWS
 * file versions in combination with the given key.  
 * 
 * @param key the file access passphrase (secret key)
 * @return <b>true</b> if and only if the socket could be opened
 *        (i.e. key matches)
 * 
 * @throws IllegalStateException if this socket is already open
 * @throws IOException if an error occurred during reading 
 */
public boolean attemptOpen ( PwsPassphrase key ) throws IOException {
   try { 
	   return attemptOpen( key, 0 ); 
   } catch ( WrongFileVersionException e ) { 
      return false;  // this should not happen as we are requesting a generic open 
   } catch ( UnsupportedFileVersionException e ) { 
      return false;  // same here 
   }
}

/**
 * Attempts to open this socket by trying a key on a PWS file of an optionally 
 * restricted format which is read from the supplied input stream starting at
 * its current position. Repeated calls to this method (open attempts) are 
 * possible as long as previous calls have all rendered negative. This method
 * allows to force a specific PWS file format version assumed.  
 * 
 * @param key the file access passphrase (secret key) 
 * @param fileVersion if not 0, the specified file version
 *        is assumed (values as in <code>Global</code>)
 * @return <b>true</b> if and only if the socket could be opened
 *        (i.e. key and version match)
 * 
 * @throws NullPointerException if passphrase is undefined
 * @throws IllegalStateException if this socket is already open
 * @throws WrongFileVersionException if a specific file format 
 *         was requested and not found to match the file (V1, V2)
 * @throws UnsupportedFileVersionException if V3 format 
 *         was requested and corrupted data was encountered   
 * @throws IOException if an error occurred during reading 
 */
public boolean attemptOpen ( PwsPassphrase key, int fileVersion )
		throws IOException, WrongFileVersionException, UnsupportedFileVersionException {
   if ( isOpen )
      throw new IllegalStateException( "socket is already open" );
   if ( isConsumed )
      throw new IllegalStateException( "socket consumed" );
   
   boolean generic = fileVersion == 0;
   
  // try V3 header format if no special request for other formats
  in.reset();
//  if ( (generic | fileVersion == Global.FILEVERSION_3) && openV3( key, generic ) ) {
	if ( openV3( key, generic ) ) {
     in.mark( 0 );
     return true;
  }
  return false;
}

/**
 * Whether this input socket is open.
 * 
 * @return <b>true</b> if and only if one of the "attemptOpen" methods has been
 *         performed successfully on this socket
 */
public boolean isOpen () {return isOpen;}

/** Tries to open this socket by use of a specified user key 
 * on the PWS file version V3 conventions. 
 * 
 * @param key <code>PwsPassphrase</code> user key to open file
 * @return <b>true</b> if and only if this socket is opened 
 *         (key success)
 * @throws NullPointerException if passphrase is undefined
 * @throws IOException if an error occurred during reading
 */
private boolean openV3 ( PwsPassphrase key, boolean generic ) 
			throws IOException, UnsupportedFileVersionException {
   try {
      // read file header section (valid for all file format versons)
      headerV3 = new PwsFileHeaderV3( in );
      headerV3.setKeySecurity(cipherKeyLength);
   
      // verify the correct user passphrase and get the encrypt cipher 
      blockStream = headerV3.verifyPass(key);
      if (blockStream == null) {
         return false;
      }
   
   } catch ( UnsupportedFileVersionException e ) {
      if ( generic ) return false;
      throw e;
   }
   
   // found the match, avoid large data buffering
   in.mark( 2048 );  

   // update member data
   headerFields = headerV3.getHeaderFields();
   hmac = headerV3.getReadHmac();
   options = headerFields.getStringValue( PwsFileHeaderV3.JPWS_OPTIONS_TYPE );
   fversion = Global.FILEVERSION_3;
   isOpen = true;
   return true;
}

/** Sets the security level for the encryption in measure of the cipher
 * key length in bits. This can be one of [64, 128, 192, 256]. The
 * default value is 256 (full security). This can be set as long as the
 * socket has not been opened.
 * 
 * @param bits int key length
 * @throws IllegalArgumentException if the length is invalid
 */
public void setKeySecurity (int bits) {
	if (blockStream != null) return;
	if (bits == 256 || bits == 128 || bits == 192 || bits == 64) {
		cipherKeyLength = bits;
	} else {
		throw new IllegalArgumentException("illegal ley-length value: " + bits);
	}
}

/** Returns the security level for the encryption in measure of the cipher
 * key length in bits. This can be one of [64, 128, 192, 256]. The
 * default value is 256 (full security).
 * 
 * @return int
 */ 
public int getKeySecurity () {return cipherKeyLength;}
/**
 * Returns the PWS file format version (for values see class <code>Global</code>) 
 * or 0 if the file has not been opened.
 * 
 * @return int file format version
 */
public int getFileVersion () {
   return fversion;
}

/**
 * Returns the blocksize of the cipher used to decrypt this socket's input 
 * stream or 0 if this socket has not been opened.
 * 
 * @return int cipher blocksize or 0
 */
public int getBlocksize () {
   return blockStream != null ? blockStream.getBlockSize() : 0;
}

/**
 * Returns a specialised iterator over all raw-fields comprising the data
 * content of the underlying PWS database. (Does not return header fields.)
 *  
 * @return <code>RawFieldReader</code>
 * @throws IllegalStateException if the socket is not open or another 
 *         input stream has been active for this socket
 * @throws IOException if an IO error occurs or the stream is corrupted        
 */
public PwsRawFieldReader getRawFieldReader () throws IOException {
   PwsBlockInputStream bs = getBlockInputStreamIntern();
   return new RawFieldReader( bs, fversion, hmac );
}

/**
 * Renders a block based input stream of the PWS file data content.
 * The blocks are resulting from the block-cipher used.
 * The stream is positioned to the first block after the file header.
 *  
 * @return <code>PwsBlockInputStream</code>
 * @throws IllegalStateException if the socket is not open or another 
 *         input stream has been active for this socket
 * @throws IOException if an IO error occurs or the stream is corrupted        
 */
public PwsBlockInputStream getBlockInputStream () throws IOException {
   PwsBlockInputStream st = getBlockInputStreamIntern();
   if ( fversion == Global.FILEVERSION_3 ) {
	  st.setStreamHmac( headerV3.getReadHmac() );
   }
   return st;
}

/**
 * Renders a block based input stream of the PWS file data content.
 * The blocks are resulting from the block-cipher used.
 * The stream is positioned to the first block after the file header.
 *  
 * @return <code>PwsBlockInputStream</code>
 * @throws IllegalStateException if the socket is not open or another 
 *         input stream has been active for this socket
 * @throws IOException if an IO error occurs or the stream is corrupted        
 */
private PwsBlockInputStream getBlockInputStreamIntern () throws IOException {
   // control access conditions
   if ( !isOpen )
      throw new IllegalStateException( "socket not open" );
   if ( userStream != null )
      throw new IllegalStateException( "input stream in use or consumed" );

   // create stream 
   userStream = blockStream;
   return userStream;
}

public void close () {
   if ( isOpen ) {
      if ( userStream != null ) {
         userStream.close();
      }
      isOpen = false;
      isConsumed = true;
   }
}

/**
 * Returns the file's options string; available when socket is open. 
 * If the file format does not support an option string, an empty 
 * string is returned.
 * <p><small>For format V2 files this value represents the same data field that 
 * is also used by PasswordSafe (PWS). For format V3 it represents a JPWS 
 * specific data field (which is not an element of the PWS canon). The PWS
 * specific preferences of a V3 file can be obtained by
 * <code>getHeaderFields().getField(PwsFileHeaderV3.PWS_PREFS_TYPE).getString("utf-8")</code>.</small>  
 * 
 * @return String file options text
 */
public String getOptions () {
   return options;
}

/** 
 * Returns the hash function verification code encountered at the end of a V3 
 * file. This code serves to verify integrity of user data. This information can
 * only be available after EOF of the input block stream has been reached; it 
 * may not be available at all.
 *  
 * @return byte[] content hash value of length 32 or <b>null</b> if this 
 * 				  information is unavailable
 */ 
 public byte[] getReadChecksum () {
    return headerV3 == null ? null : headerV3.getReadChecksum();
 }

 
 /** The number of security iterations in key calculation during file 
  * authentication. This property is only available for file format V3 and
  * after the socket has been opened
  * 
  * @return number of calculation iterations or 0 if unavailable
  */
 public int getIterations () {
    return headerV3 == null ? 0 : headerV3.getIterations();
 }

/** 
 * Returns the hash function checksum calculated over all read raw-field data
 * of a V3 file.
 * <p>This code serves to verify integrity of user data. This information can 
 * only be available after EOF of the input block stream has been reached; it 
 * may not be available at all.
 *  
 * @return byte[] file hmac of length 32 or <b>null</b> if this information is
 *                unavailable
 */ 
 public byte[] getCalcChecksum ()  {
    return hmac == null ? null : hmac.digest();
 }


/** Returns the field list of the file header if it is available. This is 
 * available only for format V3 and after the socket has been opened, 
 * otherwise null is returned.
 * <p>The header field list usually contains various data elements
 * referring to the file in total.
 * 
 * @return <code>RawFieldList</code> or <b>null</b>
 */
public HeaderFieldList getHeaderFields () {
   return headerFields;
}


/** 
  * Returns the UUID identifier for the PWS file if it is available.
  * 
  * @return file UUID or <b>null</b> if this information is not available
  */
 public UUID getFileUUID () {
    PwsRawField raw = headerFields == null ? null : 
    	  headerFields.getField( PwsFileHeaderV3.FILE_UUID_TYPE );
    return raw == null ? null : new UUID( raw.getDataDirect() );
 }

}
