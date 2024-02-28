/*
 *  File: Global.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 05.08.2004
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

package org.jpws.pwslib.global;

import java.awt.Dimension;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;

import org.jpws.pwslib.crypto.BlowfishCipher;
import org.jpws.pwslib.crypto.PwsCipher;
import org.jpws.pwslib.crypto.SHA1;
import org.jpws.pwslib.crypto.ScatterCipher;
import org.jpws.pwslib.crypto.TwofishCipher;
import org.jpws.pwslib.data.PwsFileHeaderV3;
import org.jpws.pwslib.data.PwsPassphrase;
import org.jpws.pwslib.exception.UnsupportedFileVersionException;
import org.jpws.pwslib.persist.ApplicationAdapter;
import org.jpws.pwslib.persist.DefaultFilesystemAdapter;

import kse.utilclass.misc.Log;
import kse.utilclass.misc.SHA256;
import kse.utilclass.misc.SHA512;

/**
 *  Global references for the PWSLIB backend library classes. This static 
 *  singleton class is self-initializing.  
 *  
 *  <p>Two important global objects are available: the standard application
 *  adapter and the standard encryption cipher. 
 * 
 *  <p><u>The Standard Application Adapter</u>
 *  <br>is by default the local file system adapter but may be set to 
 *  something different by the user. It is used in PWSLIB by some IO related 
 *  structures like <code>PwsFileFactory</code> and <code>PwsFile</code>.
 * 
 *  <p><u>The Standard Encryption Cipher</u>
 *  <br>is a Blowfish2 ECB 8 byte block-cipher with a random key; it is only 
 *  valid for transitional data as it is individual for each application 
 *  session.
 *  
 *  <p>See also {@link ApplicationAdapter}, {@link org.jpws.pwslib.crypto.BlowfishECB2}
 */
public final class Global {

public static final String LIBRARY_VERSION = "2.10.0";  
public static final String LIBRARY_IDENT = "KSE-PWSLIB " + LIBRARY_VERSION;  

/** Milliseconds of a day.
 */
public static final long DAY = 86400000;

/** The default value for a look-ahead time for expiring records
 *  in milliseconds. This is equivalent to 30 days.
 */
public static final long DEFAULT_EXPIRESCOPE = 20 * DAY;  

/** Identifier for PWS file format versions 3.x */
public static final int FILEVERSION_3 = 3;

/** Identifier for the latest implemented PWS file format major version (3.0) */
public static final int FILEVERSION_LATEST_MAJOR = 3;

/** Identifier for the latest implemented PWS file format minor version (3.13) */
public static final int FILEVERSION_LATEST_MINOR = 13;

/** Stream data signal for End-Of-Data in a V3 PWS file. */ 
public static final byte[] FIELDSTREAM_ENDBLOCK_V3 = "PWS3-EOFPWS3-EOF".getBytes();

private static final int MAX_DEBUG = 10;

/** Number of file blocks to be buffered in encrypted input streams. */
public static final int BLOCK_BUFFER_FACTOR = 128;

private static ApplicationAdapter standardApplication;
private static PwsCipher standardCipher;
private static String programName = LIBRARY_IDENT;
private static boolean displayUsernames; 
private static boolean isInitialized;
private static boolean haveApplications; 

static {
   init();
}

/** The identifier for the application program using this library.
 *  By default this is the library name.
 *  
 * @return String
 */
public static String getProgramName () {
   return programName;
}

/** Sets the identifier for the application program using this library.
 *  (Content is shortened to max. 60 characters.)
 *  
 *  @param name String with max. 60 char
 */
public static void setProgramName ( String name ) {
   if ( name != null ) {
      if ( name.length() > 60 ) {
         name = name.substring( 0, 60 );
      }
      programName = name;
   }
}

/** Sets the active standard application adapter (IO-context) of this 
 *  package. (See class description.)
 *  
 *  @param adp <code>ApplicationAdapter</code> new standard adapter, may be null
 */
public static void setStandardApplication ( ApplicationAdapter adp ) {
   haveApplications = adp != null;
   standardApplication = adp;
   
   if ( haveApplications && (adp.getName() == null | adp.getName().equals("")) )
      throw new IllegalArgumentException( "must have a name" );
   
   String hstr = haveApplications ? "Standard Application: " + adp.getName() 
          : "Standard Application cleared";
   Log.log( 1, "PWSLIB " + hstr );
}

/** The currently active standard application adapter (IO-context) of this 
 * package or <b>null</b> if none is defined. Class default is the 
 * adapter for the local file system.
 * 
 *  @return <code>ApplicationAdapter</code> or <b>null</b>
 */
public static ApplicationAdapter getStandardApplication () {
   return standardApplication;
}

/** Returns the standard encryption cipher of this package. This is an ECB 
 *  block-cipher and ready to use but only valid for transitional data as it is 
 *  individual for any given application session. Currently a Twofish cipher
 *  is supplied.
 * 
 *  @return <code>PwsCipher</code>
 */
public static PwsCipher getStandardCipher () {
   return standardCipher;
}

/** Returns the latest file format version that is implemented through this
 *  library. 
 *  
 * @return Dimension, width = major, height = minor version number 
 */
public static Dimension getImplicitFileVersion () {
   return new Dimension( FILEVERSION_LATEST_MAJOR, FILEVERSION_LATEST_MINOR);
}

/** The currently active default character set of the Java Virtual Machine. 
 * 
 * @return String
 */
public static String getDefaultCharset () {
	return Charset.defaultCharset().name();
}

/** Whether user names shall be displayed together with record titles.
 *  The default value is <b>false</b>.
 *  
 * @return boolean
 */
public static boolean isDisplayUsernames () {
   return displayUsernames;
}

/** Whether this class offers a value for standard application adapter.
 * 
 * @return boolean true == standard application is available
 */
public static boolean haveApplications () {
	return haveApplications;
}

/** Determines whether user names shall be displayed together with record titles.
 *  This will modify the results of <code>DefaultRecordWrapper.toString()</code>.
 *  
 *  @param v boolean <b>true</b> == display user names
 */
public static void setDisplayUsernames ( boolean v ) {
   displayUsernames = v;
}

/** Initialises global structures and settings of the PWSLIB package. This
 *  method is automatically called on first reference to this class.
 * <p><small>This 
 *  performs self-testing of the encryption algorithms and SHA hash-functions. 
 *  If tests are ok then invokes a new instance of ECB Twofish as  
 *  the standard cipher for this library and sets the default application 
 *  adapter to the local file system.</small>
 *  
 *  <p>Does nothing if this class is already initialised.
 *
 */ 
private static void init () {
   if ( !isInitialized ) {
	  setStandardApplication( DefaultFilesystemAdapter.get() );

	  String text = "CAUTION! Security-test failed! Package may be unusable";
	  boolean ok = securityTest();
	  if ( ok ) {
		  standardCipher = new TwofishCipher();
		  text = "standard cipher: ".concat(standardCipher.getName());
		  
		  packageTest();
	  }
      isInitialized = true;
      Log.log( 1, LIBRARY_IDENT.concat(" initialized; ".concat(text)));
   }
}

/** Performs self-test of the module. 
 * 
 * @return boolean true == test passed
 */
private static boolean securityTest () {
   boolean ok, ok1, ok2, ok3, ok4, ok5, ok6;

   ok1 = new SHA1().selfTest();
   ok4 = SHA256.self_test();
   ok6 = SHA512.self_test();
   ok2 = BlowfishCipher.self_test();
   ok3 = TwofishCipher.self_test();
   ok5 = ScatterCipher.self_test();
   ok = ok1 & ok2 & ok3 & ok4 & ok5 & ok6;
   
   Log.debug( 6, "SHA1 Test : " + ok1 );
   Log.debug( 6, "SHA256 Test : " + ok4 );
   Log.debug( 6, "SHA512 Test : " + ok6 );
   Log.debug( 6, "Scatter Test : " + ok5 );
   Log.debug( 6, "Blowfish Test : " + ok2 );
   Log.debug( 6, "Twofish Test : " + ok3 );

   String text = ok ? "PWSLIB selftest passed" :
	   "** PWSLIB encryption module corruption!! **\r\n** Do not use this library!! **";
   Log.debug( 1, text );
   return ok;
}

private static boolean packageTest () {
	PwsFileHeaderV3 h3 = new PwsFileHeaderV3();
	PwsPassphrase pass = new PwsPassphrase("12345678");
	ByteArrayOutputStream out = new ByteArrayOutputStream(300);
	try {
		h3.save(out, pass);
	} catch (IOException e) {
	}
	
	// attempt reading a file header (includes decryption)
	boolean ok = false;
	ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
	try {
		PwsFileHeaderV3 h3s = new PwsFileHeaderV3(in);
		ok = h3s.verifyPass(pass) != null;
	    String text = ok ? "PWS3 file header tested OK" : "** PWS3 file header test FAILED";
		Log.debug( 1, text );
	} catch (UnsupportedFileVersionException e) {
		e.printStackTrace();
	} catch (IOException e) {
		e.printStackTrace();
	}
	return ok;
}

private Global () {
}
   
/**
 * This performs a short self-testing verification of crucial library functions.
 * 
 * @param args String[]
 */   
public static void main ( String[] args ) {
   Log.setLogLevel(10);
   Log.log(0, "Default Charset: ".concat(getDefaultCharset()));
   Log.log(0, "Standard Cipher: ".concat(getStandardCipher().getName()));
   Dimension ver = getImplicitFileVersion();
   Log.log(0, "Supported PWS version: " + ver.width + "." + ver.height);
}

}
