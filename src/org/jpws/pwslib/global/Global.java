/*
 *  Global in org.jpws.pwslib.global
 *  file: Global.java
 * 
 *  Project JPasswords
 *  @author Wolfgang Keller
 *  Created 05.08.2004
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

package org.jpws.pwslib.global;

import java.awt.Dimension;
import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;

import org.jpws.pwslib.crypto.BlowfishCipher;
import org.jpws.pwslib.crypto.PwsCipher;
import org.jpws.pwslib.crypto.SHA1;
import org.jpws.pwslib.crypto.SHA256;
import org.jpws.pwslib.crypto.TwofishCipher;
import org.jpws.pwslib.persist.ApplicationAdapter;
import org.jpws.pwslib.persist.DefaultFilesystemAdapter;

/**
 *  Global references for the pwslib backend library classes. This singleton class is 
 *  self-initializing. The debug and log level of the <code>Log</code> class
 *  are set to default value 1. 
 *  
 *  <p>Two important global objects are available: the standard application
 *  adapter and the standard encryption cipher. 
 * 
 *  <p><u>The Standard Application Adapter</u>
 *  <br>is by default the local file system adapter but may be set to 
 *  something different. It is used in PWSLIB by some IO related 
 *  structures like <code>PwsFileFactory</code> and <code>PwsFile</code>.
 * 
 *  <p><u>The Standard Encryption Cipher</u>
 *  <br>is a Blowfish2 ECB 8 byte block-cipher but only valid for
 *  transitional data as it is individual for any given application session.
 *  
 *  <p>See also {@link ApplicationAdapter}, {@link org.jpws.pwslib.crypto.BlowfishECB2}
 */
public final class Global
{

public static final String LIBRARY_VERSION = "2.2.0";  
public static final String LIBRARY_IDENT = "KSE-PWSLIB " + LIBRARY_VERSION;  

/** Milliseconds of a day.
 *  @since 0-3-0
 *  */
public static final long DAY = 86400000;

/** The default value for a look-ahead timespan for expiring records
 *  in milliseconds. This is equivalent to 30 days.
 *  @since 0-3-0
 *  */
public static final long DEFAULT_EXPIRESCOPE = 30 * DAY;  

/** Whether the standard application adapter (IO-context) is defined. */
public static boolean haveApplications; 

/** Identifier for PWS file format versions 1.x */
public static final int FILEVERSION_1 = 1;

/** Identifier for PWS file format versions 2.x */
public static final int FILEVERSION_2 = 2;

/** Identifier for PWS file format versions 3.x */
public static final int FILEVERSION_3 = 3;

/** Identifier for the latest implemented PWS file format major version (3.0) */
public static final int FILEVERSION_LATEST_MAJOR = 3;

/** Identifier for the latest implemented PWS file format minor version (3.10) */
public static final int FILEVERSION_LATEST_MINOR = 10;

/** Stream data signal for End-Of-Data in a V3 PWS file. */ 
public static final byte[] FIELDSTREAM_ENDBLOCK_V3 = "PWS3-EOFPWS3-EOF".getBytes();

private static final int MAX_DEBUG = 10;

private static ApplicationAdapter standardApplication;
private static PwsCipher standardCipher;
private static String programName = LIBRARY_IDENT;
private static boolean displayUsernames; 
private static boolean isInitialized;

static {
   init();
}

/** The identifier for the application program using this library.
 *  By default this is the library name.
 *  @since 2-1-0
 */
public static String getProgramName ()
{
   return programName;
}

/** Sets the identifier for the application program using this library.
 *  (Content is shortened to max. 60 characters.)
 *  @param name String with max. 60 char
 *  @since 2-1-0
 */
public static void setProgramName ( String name )
{
   if ( name != null )
   {
      if ( name.length() > 60 )
         name = name.substring( 0, 60 );
      programName = name;
   }
}

/** Sets the active standard application adapter (IO-context) of this 
 *  package. (See class description.)
 *  @since 0-3-0
 *  */
public static void setStandardApplication ( ApplicationAdapter adp )
{
   String hstr;
   
   haveApplications = adp != null;
   standardApplication = adp;
   
   if ( haveApplications && (adp.getName() == null | adp.getName().equals("")) )
      throw new IllegalArgumentException( "must have a name" );
   
   hstr = haveApplications ? "Standard Application: " + adp.getName() 
          : "Standard Application cleared";
   Log.log( 1, "(Global) " + hstr );
}

/** The currently active standard application adapter (IO-context) of this package. */
public static ApplicationAdapter getStandardApplication ()
{
   return standardApplication;
}

/** Returns the standard encryption cipher of this package. This is an ECB 
 *  block-cipher and ready to use but only valid for transitional data as it is 
 *  individual for any given application session.
 * 
 *  @return Blowfish <code>PwsCipher</code>
 */
public static PwsCipher getStandardCipher ()
{
   return standardCipher;
}

/** Returns the latest file format version that is implemented through this
 *  library. 
 * @return Dimension, width = major, height = minor version number 
 * @since 2-2-0
 */
public static Dimension getImplicitFileVersion ()
{
   return new Dimension( FILEVERSION_LATEST_MAJOR, FILEVERSION_LATEST_MINOR);
}

/** The currently active default character set of the Java Virtual Machine. */
public static String getDefaultCharset ()
{
   return new OutputStreamWriter(new ByteArrayOutputStream()).getEncoding();
}

/** Whether user names shall be displayed together with record titles.
 *  The default value is <b>false</b>.
 *  @since 0-3-0
 *  */
public static boolean isDisplayUsernames ()
{
   return displayUsernames;
}

/** Determines whether user names shall be displayed together with record titles.
 *  This will modify the results of <code>DefaultRecordWrapper.toString()</code>.
 *  @param v <b>true</b> == display user names
 *  @since 0-3-0
 */
public static void setDisplayUsernames ( boolean v )
{
   displayUsernames = v;
}

/** Initializes global structures and settings of the PWSLIB package. This 
 *  performs self-testing of the encryption algorithms and SHA hash-functions. 
 *  If ok then invokes a new instance of an ECB Blowfish2 cipher as a  
 *  global standard cipher operational for this library.
 *  
 *  <p>Does nothing if this class is already initialized.
 *
 */ 
public static void init ()
{
   boolean ok1, ok2, ok3, ok4;
   
   if ( !isInitialized )
   {
      Log.setDebugLevel( 1 );
      Log.setLogLevel( 1 );

      ok1 = new SHA1().selfTest();
      ok4 = SHA256.self_test();
      ok2 = BlowfishCipher.self_test();
      ok3 = TwofishCipher.self_test();
      Log.debug( 9, "SHA1 Test : " + ok1 );
      Log.debug( 9, "SHA256 Test : " + ok4 );
      Log.debug( 9, "Blowfish Test : " + ok2 );
      Log.debug( 9, "Twofish Test : " + ok3 );
      
      if ( !(ok1 & ok2 & ok3 & ok4) )
         throw new IllegalStateException("** encryption module corruption **");
      
      standardCipher = new BlowfishCipher();
      setStandardApplication( DefaultFilesystemAdapter.get() );

      isInitialized = true;
      Log.log( 1, "(Global) Global initialized");
   }
}

private static void securityTest ()
{
   boolean ok1, ok2, ok3, ok4;

   ok1 = new SHA1().selfTest();
   ok4 = SHA256.self_test();
   ok2 = BlowfishCipher.self_test();
   ok3 = TwofishCipher.self_test();
   
   Log.debug( 1, "SHA1 Test : " + ok1 );
   Log.debug( 1, "SHA256 Test : " + ok4 );
   Log.debug( 1, "Blowfish Test : " + ok2 );
   Log.debug( 1, "Twofish Test : " + ok3 );
   
   if ( !(ok1 & ok2 & ok3 & ok4) )
      Log.debug( 1, "** PWSLIB encryption module corruption!! **\r\n** Do not use this library!! **" );
   else
      Log.debug( 1, "PWSLIB selftest passed" );
}


private Global ()
{}
   
/**
 * This is meant for short self-testing verification of  
 * crucial library functions.
 * 
 * @param args
 */   
public static void main ( String[] args )
{
   securityTest();
}

}
