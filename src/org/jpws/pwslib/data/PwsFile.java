/*
 *  file: PwsFile.java
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

import java.awt.Dimension;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Iterator;

import org.jpws.pwslib.crypto.SHA256;
import org.jpws.pwslib.exception.ApplicationFailureException;
import org.jpws.pwslib.global.Global;
import org.jpws.pwslib.global.Log;
import org.jpws.pwslib.global.UUID;
import org.jpws.pwslib.global.Util;
import org.jpws.pwslib.order.DefaultRecordWrapper;
import org.jpws.pwslib.persist.ApplicationAdapter;

/**
 *  Top level structure of this library to represent a <i>PasswordSafe</i> (PWS)
 *  database file. 
 *  
 *  <p>This class is an extension of a record list ({@link PwsRecordList}),
 * hence data of all records is kept in memory, eventually causing restrictions
 * on the amount of records that can be kept in an application.  
 * The extension deals with all definitions required to represent or create
 * a "persistent state" (PWS file) of a record list on an external medium.
 * It also allows to define a set of up to 255 <b>"header fields"</b> which 
 * are data elements on a list generic level.
 * 
 * <p><u>Persistent State</u> 
 * <p>The <b><i>persistent state</i></b> is <u>defined</u>/identified by a quadruple: 
 * i) a filename (filepath), 
 * ii) a related IO-context (application adapter),
 * iii) an access passphrase, 
 * and iv) a file format version. 
 * Using {@link ApplicationAdapter} is a fairly abstract conception to access 
 * peripheral media, which can be easily adapted to any user context. The full definition 
 * of a persistent state is however not mandatory to use an instance of <code>PwsFile</code>.
 * This class ensures that there are always valid settings for application adapter and
 * file format.
 * 
 * <p><u>File IO:</u> 
 * <p>Persistent states are accessed through data streams which are made
 * available by application adapters. The concrete handling of file-IO
 * and data formatting is handled by class {@link PwsFileFactory}.  
 * To obtain an instance of this class from its persistent state, use the static
 * <code>PwsFileFactory.loadFile()</code> methods. To create a persistent state
 * use the <code>save()</code> or <code>saveCopy()</code> methods of this class 
 * when all required parameters for the persistent state are available.
 * If a loaded file was of a different format version, or some indication of potential
 * data loss occurred during loading, the next save will make an attempt to preserve 
 * the existing file by adding a name extention ".old".
 *
 *  <p><u>File Formats</u>
 * <p>This class now supports reading and writing of all three historical, major 
 * file format versions of <i>PasswordSafe</i>. The following policy is adopted
 * concerning these formats. Files loaded from a persistent state (via <code>
 * PwsFileFactory</code>) feature the format version of the persistent state. 
 * New instances (not loaded) feature the latest available format version.
 * File saving produces an output format version as currently set in the 
 * <code>PwsFile</code> object.
 * At any time the user can modify the file format setting of an instance without 
 * restrictions. Downgrading a file version will, however, likely result in loss
 * of record data that is not supported in the older format.  
 *  
 * <p><u>Header Fields</u>
 * <p>Since library version 2-0-0 (and PWS format version 3) a facility for up to
 * 255 data fields, each of free length and type, is supported by <code>PwsFile</code>.
 * This is a handy way of making file generic information available which may be
 * application specific. Through <code>getHeaderFields()</code> the user gets 
 * hold of a {@link HeaderFieldList} containing elements of type
 * {@link PwsRawField}. This list can be mined for and manipulated with data; 
 * however it will only be stored on a persistent state in file format V3.
 * There are several reserved data fields defined by PWS and JPWS. The user of
 * this library should not define proprietary fields in the range 0x00 .. 0x7F.
 *  
 * <p><u>User Options:</u>
 * <p>User options take the form of a text string and are now stored as an element 
 * of the header field list (field-ID is <code>PwsFileHeaderV3.JPWS_OPTIONS_TYPE</code>). 
 * These options are reflected both into V3 and V2 files. For V2 files 
 * options also may contain the <i>PasswordSafe Preferences</i> (special options 
 * of the program PWS); for V3 files <i>PWS Preferences</i> are stored 
 * in a special header field and may be accessed by field-ID 
 * <code>PwsFileHeaderV3.PWS_PREFS_TYPE</code>.
 * 
 * <p><u>Universal Encoding:</u>
 * <p>As of file format version V3 all text data is stored in universal encoding
 * (UTF-8). File format V2 (which is deprecated)
 * stores text in UTF-8 only if "B 24 1" is contained within the <i>PasswordSafe Preferences</i>,
 * otherwise it uses the current JVM default encoding (which may be locale
 * specific).
 * 
 * @see PwsFileFactory
 * @see ApplicationAdapter
 */
public class PwsFile extends PwsRecordList implements Cloneable
{
   /** Minimum number of security calculation loops for access key verification. 
    * @since 2-1-0 */
   private static final int SECURITY_ITERATIONS_MINIMUM = 2048;

   /** Maximum number of security calculation loops for access key verification. 
   * @since 2-1-0 */
   private static final int SECURITY_ITERATIONS_MAXIMUM = 2048 * 2048;
   
   /** 
    * The application adapter representing the context of the file's
    * persistency state.
    */
   private ApplicationAdapter application;
   
   /** 
	 * The fully qualified path to the file.
	 */
   private String		   filePath;

   /**
     * The (persistent) file access passphrase.
     */
   private PwsPassphrase   ps;

   /** 
    * File version number (major figure).
    * @since 2-0-0
    */
   private int             fileVersionMajor = Global.FILEVERSION_LATEST_MAJOR;

   /** 
    * File version number (minor figure).
    * @since 2-2-0
    */
   private int             fileVersionMinor = Global.FILEVERSION_LATEST_MINOR;

   /** 
    * File version number of the load source.
    * @since 2-0-0
    */
   private int             sourceFormat;
   
   /** 
    * Number of calculation loops during file access authentication.
    * @since 2-1-0
    */
   private int             securityLoops = SECURITY_ITERATIONS_MINIMUM;
   
   /**
    * Whether the V3 file trailing checksum was verified OK.
    * (False for V2 and V1 files.) 
    */
   private boolean         checksumOK = true;

   /** 
    * A list of rawfields forming the file's header fields.
    * (This is a feature of the V3 file format.) 
    * @since 2-0-0
    */
   private HeaderFieldList     headerFields = new PFHeaderFieldList(); 
   
   /**
    * Flag indicating whether an attempt should be made to preserve an 
    * existing persistent file state by renaming it as ".old" copy 
    * during any save operation.
    */
   private boolean         preserveOld;

   
	/**
	 * Constructs a new, empty PWS database for the standard
    * IO-context (by default the local file system) but with a void 
    * definition of the persistent state. (Note that filepath and passphrase 
    * have to be set up before this file can be saved.) 
    * 
    * @throws IllegalStateException if no global standard application is available
	 */
	public PwsFile()
	{
      super();
      initBasic();
      
      Log.log( 2, "(PwsFile) new standard PwsFile: ID = " + fileID );
	}  // constructor

    /**
     * Constructs a new PWS database with an initial
     * record content as represented by the parameter record wrapper array. 
     * Duplicate records in the array are silently ignored; no check for 
     * record validity is performed.
     * 
     * @param recs array of <code>DefaultRecordWrapper</code> objects;
     *        may be <b>null</b>
     * @since 0-4-0       
     */
    public PwsFile( DefaultRecordWrapper[] recs )
    {
       super( recs );
       initBasic();

       Log.log( 2, "(PwsFile) new PwsFile (with record set): ID = " + fileID );
    }  // constructor

   /**
    * Constructs a fully defined, empty PWS database with
    * all required references for an external persistent state.
    * 
    * @param appl <code>ApplicationAdapter</code> the IO-context used to save
    *        the persistent state of this file
    * @param filepath the full filepath specification for the persistent state
    * @param userpass a <code>PwsPassphrase</code> object defining the access
    *        passphrase used to encrypt the content
    * 
    * @throws IllegalArgumentException if any param is void
    */
   public PwsFile ( ApplicationAdapter appl,
                    String filepath, 
                    PwsPassphrase userpass )
   {
      super();
      initFull(appl, filepath, userpass);
   } // constructor

   /**
    * Constructs a fully defined, empty PWS database with
    * the standard application IO-context (by default the local file system).
    * 
    * @param filepath the full filepath specification for the persistent state
    * @param userpass a <code>PwsPassphrase</code> object defining the access
    *        passphrase used to encrypt the content
    * 
    * @throws IllegalArgumentException if any param is void
    * @throws IllegalStateException if no global standard application is available
    */
   public PwsFile ( String filepath, 
                    PwsPassphrase userpass )
   {
      initBasic();
      initFull(application, filepath, userpass);
   }  // constructor

   private void initBasic ()
   {
      // install global default application adapter
      if ( (application = Global.getStandardApplication()) == null )
         throw new IllegalStateException( "no standard application available" );
      
      // take over UUID from super class into header fields
      headerFields.setField( new PwsRawField( 1, getUUID().getBytes() ) );
      resetModified();
   }
   
   private void initFull ( ApplicationAdapter appl,
                               String filepath, 
                               PwsPassphrase userpass )
   {
      if ( appl == null )
         throw new IllegalArgumentException( "application missing" );
      if ( filepath == null || filepath.equals("") )
         throw new IllegalArgumentException( "filepath missing" );
      if ( userpass == null )
         throw new IllegalArgumentException( "passphrase missing" );

      application = appl;
      filePath = filepath;
      setPassphrase( userpass );

      // take over UUID from super class into header fields
      headerFields.setField( new PwsRawField( 1, getUUID().getBytes() ) );
      resetModified();

      Log.log( 2, "(PwsFile) new PwsFile: ID = " + fileID + ", external: " + 
               extFileRef(application, filePath) );
   }  // initInstance
   
   /**
    * Returns a shallow clone of this file structure (PwsFile). 
    * File-ID number is modified to be unique and any 
    * registered listeners are removed from the clone. The stored
    * passphrase is a copy; UUID is the same.
    * 
    * @return object of type <code>PwsFile</code>
    * @since 2-1-0
    */
   public Object clone ()
   {
      PwsFile file;
      
      if ( (file = (PwsFile) super.clone()) == null )
         return null;
      
      file.headerFields = (HeaderFieldList) headerFields.clone();
      file.ps = (PwsPassphrase)ps.clone();
      
      Log.log( 2, "(PwsFile) new PwsFile (clone of " + idString + 
               "): ID = " + file.idString );
      return file;
   }

   /**
    * Returns a deep clone of this file structure (PwsFile).
    * All records of the returned list are copies of the original. 
    * File-ID number is modified to be unique and any 
    * registered listeners are removed from the clone. The stored
    * passphrase is a copy; UUID is the same.
    * 
    * @return object of type <code>PwsFile</code>
    * @since 2-1-0
    */
   public Object copy ()
   {
      PwsFile file;
      Iterator it;
      
      file = (PwsFile) clone();

      try {
         file.clear();
         for ( it = iterator(); it.hasNext(); )
            file.addRecord( (PwsRecord)it.next() );
      }
      catch ( Exception e )
      {
         throw new IllegalStateException( "list copy error: " + e.getMessage() );
      }
      
      Log.log( 2, "(PwsFile) create copy of " + idString + 
               ": ID = " + file.idString );
      return file;
   }

   /**
    * This method replaces entire content of this file, including all settings,
    * by the contents of the parameter file. Works as a shallow clone of the record list
    * and shares identity with the parameter file.
    *   
    * @param f <code>PwsFile</code> new content for this file
    */
   public void replaceFrom ( PwsFile f )
   {
      boolean p;
      
      super.replaceFrom( f );
      application = f.application;
      filePath = f.filePath;
      checksumOK = f.checksumOK;
      preserveOld = f.preserveOld;
      fileVersionMajor = f.fileVersionMajor;
      fileVersionMinor = f.fileVersionMinor;
      securityLoops = f.securityLoops;
      sourceFormat = f.sourceFormat;
      if ( f.ps != null )
         ps = (PwsPassphrase)f.ps.clone();

      p = getEventPause();
      setEventPause( true );
      headerFields.clear();
      for ( Iterator it = f.headerFields.iterator(); it.hasNext(); )
         headerFields.setField( (PwsRawField)it.next() );
//      headerFields = (HeaderFieldList)f.headerFields.clone();
      setEventPause( p );
      modified = f.modified;
   }
   
	/**
    * Returns the file name (full path) of the persistent state of this file or <b>null</b> 
    * if it is not defined.
    */
   public final String getFilePath()
   {
      return filePath;
   }

   /**
    * Returns the file name (last path element) of the persistent state of this file or <b>null</b> 
    * if it is not defined.
    * 
    * @since 2-1-0
    */
   public final String getFileName()
   {
      return filePath == null ? null : new File( filePath ).getName();
   }

	/**
	 * Returns the format version number for this file. The default format
     * of a new file is <code>Global.FILEVERSION_LATEST_MAJOR</code>.
	 * 
	 * @return int format number (values defined in class <code>Global</code>)
     * 
     * @since 2-0-0
	 */
	public final int getFormatVersion()
   {
      return fileVersionMajor;
   }

	/**
	 * Returns the format information for this file, containing both major
	 * and minor version numbers.
	 * 
	 * @return Dimension, width = major, height = minor version number 
	 * @since 2-2-0
	 */
	public final Dimension getFileFormat ()
	{
	   return new Dimension( fileVersionMajor, fileVersionMinor );
	}
	
    /**
     * Returns the activated character set used to encode text strings on the persistent state.
     * (The charset is "Utf-8" for V3 file format (fixum) or for V2 format if "B 24 1" is present in
     * user options. It is the VM default character set otherwise.)
     *  
     * @return String charset name
    * @since 2-0-0
     */ 
    public String getCharset ()
    {
       return fileVersionMajor > Global.FILEVERSION_2 || 
              (fileVersionMajor == Global.FILEVERSION_2 & getUserOptions().indexOf( "B 24 1" ) > -1) ? 
              "Utf-8" : Global.getDefaultCharset();
    }
    
   /**
    * Sets the format version number for the file. This value determines
    * the technical file format of the persistent state of this file.
    * By default (for a new instance) the latest available format version
    * is active. This is (normally) a fast returning operation.
    * 
    * @param value the file format code (use one of the values defined in class <code>Global</code>)
    *        or 0 for latest format
    * @since 2-0-0
    */
   public synchronized void setFormatVersion( int value )
   {
      int oldVersion;
      
      if ( value < 1 | value > Global.FILEVERSION_3 )
         value = Global.FILEVERSION_LATEST_MAJOR;

      if ( value != fileVersionMajor )
      {
         // assign new format
         oldVersion = fileVersionMajor;
         fileVersionMajor = value;
         
         // if upgrade from earlier version then remove unknown fields
         if ( oldVersion < fileVersionMajor )
            clearUnknownFields();
         
         // if switch to V3 format AND there is no UUID defined in header fields
         // then store UUID from PwsRecordList into relevant header field
         if ( value == Global.FILEVERSION_3 && 
              headerFields.getField( PwsFileHeaderV3.FILE_UUID_TYPE ) == null )
            headerFields.setField( new PwsRawField( PwsFileHeaderV3.FILE_UUID_TYPE, 
                  getUUID().getBytes() ));

         // inform object and listeners of modification
         contentModified();
      }
   }

	/**
	 * Returns the encryption passphrase used on this file (file access passphrase).
	 * 
	 * @return a copy of the file's access passphrase or <b>null</b> if it is not defined
	 */
	public final PwsPassphrase getPassphrase()
	{
		return ps == null ? null : (PwsPassphrase) ps.clone();
	}

   /**
    * Returns the application adapter (IO-context) to which this file is linked.
    * 
    * @return ApplicationAdapter, the IO-context 
    */
   public final ApplicationAdapter getApplication()
   {
      return application;
   }
   
   /**
    * Returns a <code>ContextFile</code> representation of this database's
    * persistent state definition.
    * 
    * @return <code>ContextFile</code> or <b>null</b> if unavailable
    * @since 2-1-0
    */
   public ContextFile getContextFile ()
   {
      return hasResource() ? new ContextFile( getApplication(), getFilePath() ) : null;
   }

   /**
    * Returns the last modification time of the persistent state of this 
    * file. 
    *  
    * @return last modification time or 0 if there exists no persistent state
    *         or this information is not available
    * @throws IOException
    * @since 0-3-0
    */
   public long lastModified () throws IOException
   {
      return hasResource() ? application.getModifiedTime( filePath ) : 0;
   }

   /**
    * Returns the total data size of all unknown (non-canonical) fields
    * in this record list. (This refers to nominal field data sizes.)
    * 
    * @return long unknown data size
    * @since 2-0-0 
    */
   public long getUnknownFieldSize ()
   {
      return super.getUnknownFieldSize( fileVersionMajor ) 
             + headerFields.getUnknownFieldSize( fileVersionMajor );
   }

   /**
    * Returns the number of datafields which are kept as non-canonical 
    * in this list of records.
    * 
    * @return int number of non-canonical records
    * @since 2-0-0 
    */
   public int getUnknownFieldCount ()
   {
      return super.getUnknownFieldCount() + headerFields.getUnknownFieldCount();
   }

   /** Clears away all non-canonical fields from this database, including unknown header 
    * fields. 
    * @since 2-0-0
    */
   public void clearUnknownFields ()
   {
      int ctrl;
      
      super.clearUnknownFields();
      
      // clear UKF in headerfield list
      ctrl = headerFields.size();
      headerFields.clearUnknownFields();
      if ( headerFields.size() != ctrl )
         contentModified();
   }
   
   /**
    * Returns the size of the data block required to store the content of
    * this database on a persistent state. (This takes into respect the 
    * general file formating rules of a PWS file of the specified format.) 
    * This is a relatively expensive operation as it walks through analysing 
    * all records with each call.
    * 
    * @param format the file format version of the persistent state
    * @return int required (blocked) data space
    * @since 2-0-0
    */
   public long getBlockedDataSize ( int format )
   {
      long sum;
      String charset;
      
      // sum-up of record content 
      charset = getCharset();
      sum = super.getBlockedDataSize( format, charset );

      // constant file overhead
      switch ( format )
      {
      case Global.FILEVERSION_1:
         sum += 56;
         break;
      case Global.FILEVERSION_2:
         sum += 56 + 12 * 8;
         try { sum += PwsRawField.pwsFieldBlockSize( getUserOptions().getBytes( charset ).length, format ); }
         catch ( UnsupportedEncodingException e )
         {}
         break;
      case Global.FILEVERSION_3:
         sum += headerFields.blockedDataSize( format );
         sum += 152 + 48;
         break;
      }

      return sum;
   }

	/**
	* Writes this file to its persistent state in the linked 
    * IO-context. This method requires that the persistent state of
    * this file is fully defined. After successful operation, the 
    * "modified" flag is reset to <b>false</b>. This method does 
    * nothing if the "modified" flag is already <b>false</b>.
    * <p><small>The persistent state of a file is defined by 
    * application adapter, filepath and access passphrase.</small>
	 * 
    * @throws IllegalStateException if the required parameters for the
    *         persistent state are undefined  
    * @throws IOException if an IO-error occurs
    * @throws ApplicationFailureException if the IO-context fails to render
    *         an output stream 
	 */
	public synchronized void save() throws IOException, ApplicationFailureException
	{
	   String hstr;
      
      if ( isModified() )
      {
         if ( application == null | filePath == null | ps == null )
            throw new IllegalStateException( "persistent state parameters not set" );
         
         if ( (sourceFormat != 0 & fileVersionMajor != sourceFormat) | preserveOld )
         {
            try {
               // preserve a copy of the previous version of the file
               hstr = filePath + ".old";
               
               Log.log( 5, "(PwsFile) renaming previous file to : " + hstr ); 
               if ( application.renameFile( filePath, hstr ) )
                  Log.debug( 2, "renamed " + filePath + " to: " + hstr );
               else
                  Log.error( 2, "unable to rename file " + filePath +
                        ", target: " + hstr );
            }
            catch ( Exception e )
            {}
         }

         // save content of this file
         hstr = idString + extFileRef(application, filePath);
         
         Log.log( 4, "(PwsFile) saving file to" + hstr ); 
         PwsFileFactory.saveFile( iterator(), application, filePath, ps, headerFields, 
               securityLoops, fileVersionMajor );
   	     resetModified();
         Log.log( 4, "(PwsFile) file save finished (before event dispatch)");
         
         fireFileEvent( PwsFileEvent.LIST_SAVED, null );
         
         Log.debug( 2, "(PwsFile.save) file saved to: " + hstr ); 
      }
	}  // save

   /**
    * Writes a copy of this file to a specified file of a specified medium, applying 
    * the same passphrase as is defined for this file.  
    * The copy will own a different UUID identifier.
    *
    * @param app the application context in which the target file will be created;
    *        if <b>null</b> then the same application is referred to as is defined
    *        for <b>this</b> file  
    * @param filepath the file name specification (relative to <code>app</code>) for 
    *        the target file
    * 
    * @return UUID the file identifier value of the copy or <n>null</b> if unavailable
    * @throws IllegalArgumentException if <code>filepath</code> or the file
    *         passphrase are not defined
    * @throws IOException if an IO-error occurs
    * @throws ApplicationFailureExeption if the IO-context fails to render
    *         an output stream 
    */
   public synchronized UUID saveCopy( ApplicationAdapter app, String filepath ) 
         throws IOException, ApplicationFailureException
   {
      return saveCopy( app, filepath, null, 0, false );
   }

   /**
    * Writes a copy of this file to a specified file of a specified medium, 
    * allowing to setup a different access passphrase for the copy. 
    * The copy will own a different UUID identifier.
    *
    * @param app the application context in which the target file will be created;
    *        if <b>null</b> then the same application is referred to as defined
    *        for <b>this</b> file  
    * @param filepath the file name specification (valid for <code>app</code>) for 
    *        the target file
    * @param pass an optional passphrase for the copy; if <b>null</b> the passphrase
    *        of this file is used       
    * 
    * @return UUID the file identifier value of the copy or <n>null</b> if unavailable
    * @throws IllegalArgumentException if <code>filepath</code> or the file
    *         passphrase are not defined
    * @throws IOException if an IO-error occurs
    * @throws ApplicationFailureExeption if the IO-context fails to render
    *         an output stream 
    * @since 0-3-1        
    */
   public synchronized UUID saveCopy( ApplicationAdapter app, String filepath,
         PwsPassphrase pass ) 
         throws IOException, ApplicationFailureException
   {
      return saveCopy( app, filepath, pass, 0, false );
   }

   /**
    * Writes a copy of this file to a specified file of a specified medium, allowing to 
    * setup a different passphrase and a different file format version for the copy . 
    *
    * @param app the application context in which the target file will be created;
    *        if <b>null</b> then the same application is referred to as defined
    *        for <b>this</b> file  
    * @param filepath the file name specification (valid for <code>app</code>) for 
    *        the target file
    * @param pass an optional passphrase for the copy; if <b>null</b> the passphrase
    *        of this file is used
    * @param format the target file format version or 0 for this file's actual 
    *        format setting   
    * @param preserveUUID if <b>true</b> the existing UUID will be the same in the copy
    *        otherwise a new one is created; V3 only                  
    * @return UUID the file identifier value of the saved file or <b>null</b> if unavailable
    * 
    * @return UUID the file identifier value of the copy or <n>null</b> if unavailable
    * @throws IllegalArgumentException if <code>filepath</code> or the file
    *         passphrase are not defined
    * @throws IOException if an IO-error occurs
    * @throws ApplicationFailureExeption if the IO-context fails to render
    *         an output stream 
    * @since 2-0-0        
    */
   public synchronized UUID saveCopy( ApplicationAdapter app, String filepath,
         PwsPassphrase pass, int format, boolean preserveUUID ) 
         throws IOException, ApplicationFailureException
   {
      HeaderFieldList headers;
      UUID fid;
      String hstr;
      
      // some default constitutive values from original
      if ( app == null )
         app = application;
      if ( pass == null )
         pass = ps;
      if ( format == 0 )
         format = fileVersionMajor;

      // we copy the headers to prevent update events striking through to the original 
      headers = new HeaderFieldList( headerFields );
      
      if ( format == Global.FILEVERSION_3 & !preserveUUID )
      {
         // this will trigger creation of a new UUID for the copy
         headers.removeField( 1 ); 
      }
      
      Log.log( 2, "(PwsFile) saving a file copy to" + idString  + extFileRef(app, filepath)); 
      fid = PwsFileFactory.saveFile( iterator(), app, filepath, pass, headers, securityLoops, format );
      hstr = headers.contains( 1 ) ? Util.bytesToHex( headers.getField( 1 ).getData() ) : "void";
      Log.log( 2, "(PwsFile) copy done, target UUDI = " + hstr ) ; 
      
      return fid;
   }

   /**
    * Returns a human info file path notation incorporating the IO-context name.
    */
   protected String extFileRef ( ApplicationAdapter app, String filePath )
   {
      return "\"" + app.getName() + "\" -> " + filePath;
   }
   
   /**
	 * Sets the name of the datafile that contains the persistent state of this file.
     * Use <b>null</b> to clear.
	 * 
	 * @param path the name for the file, may be <b>null</b> but not empty
    * @throws IllegalArgumentException is the parameter value is empty
	 */
	public synchronized void setFilePath( String path )
	{
      if ( path != null && path.equals("") )
         throw new IllegalArgumentException("empty filename");
      
	  filePath = path;
      setModified();
      Log.debug( 2, "(PwsFile) file path modified to" + idString  + filePath ); 
      fireFileEvent( PwsFileEvent.TARGET_ALTERED, null );
   }


   /**
    * Sets the application adapter (IO-context) for this file.
    * 
    * @param app the new application context valid for this file
    * @throws IllegalArgumentException is the parameter is void
    */
   public synchronized void setApplication( ApplicationAdapter app )
   {
      if ( app == null )
         throw new NullPointerException();
      
      application = app;
      setModified();
      Log.debug( 2, "(PwsFile) file IO-context modified to: " + app.getName() ); 
      fireFileEvent( PwsFileEvent.TARGET_ALTERED, null );
   }

   /** Sets application adapter and filepath of this file
    * from the parameter context file.
    * @param f <code>ContextFile</code>
    */
   public synchronized void setPersistentFile ( ContextFile f )
   {
      if ( f == null ) 
          filePath = null;
      else
      {
         application = f.getAdapter();
         filePath = f.getFilepath();
      }
      setModified();
      Log.debug( 2, "(PwsFile) file context-file modified to: " 
                 + (f==null ? null : f) ); 
      fireFileEvent( PwsFileEvent.TARGET_ALTERED, null );
   }
   
   /**
    * Returns a text String with file specific options set by the user.
    * <p><small>The policy of this value is the following: for format V2
    * files it represents the same data field that is also used by
    * PasswordSafe (PWS). For format V3 it represents a JPWS specific 
    * data field (which is not an element of the PWS canon). The PWS
    * specific preferences of a V3 file can be obtained by 
    * <code>getHeaderFields().getField(PwsFileHeaderV3.PWS_PREFS_TYPE).getString("utf-8")</code>.
    * V1 format does not support an option string.</small>  
    *  
    * @return String with user options; empty string if undefined 
    */
   public String getUserOptions ()
   {
      PwsRawField raw;
      String options;
      
      
      raw = headerFields.getField( PwsFileHeaderV3.JPWS_OPTIONS_TYPE );
      options = raw == null ? "" : raw.getString( "utf-8" );  

      if ( Log.getLogLevel() > 6 )
      Log.log( 7, "(PwsFile) returning user options = \"" + options + "\"" );
      return options;
   }

   /**
    * Sets the user options for this file. 
    * <p><small>Note concerning the persistent state: 
    * For V2 files this will set the PWS preferences header field. For
    * V3 files it will set a JPWS specific field (which is not an 
    * element of the PWS canon). The PWS preferences (String x) of a V3 file
    * can be set by
    * <code>getHeaderFields().setField(new PwsRawField(PwsFileHeaderV3.PWS_PREFS_TYPE,x.getBytes("utf-8")))</code>.
    * V1 format does not support an option string.</small> 
    * 
    * @param options String, may be <b>null</b> to clear an assignment
    */
   public synchronized void setUserOptions ( String options )
   {
      if ( options == null )
         options = "";

      Log.log( 7, "(PwsFile) setting user options = \"" + options + "\"" );
//      Log.debug( 7, "(PwsFile.setUserOptions) old user options = \"" + getUserOptions() + "\"" );
      if ( !options.equals( getUserOptions() ) )
      {
         setModified();
         try{ 
            headerFields.setField( new PwsRawField( PwsFileHeaderV3.JPWS_OPTIONS_TYPE, options.getBytes("utf-8") )); 
            contentModified();
         }
         catch ( UnsupportedEncodingException e )
         {}
      }
   }
   
   /**
    * Sets the user passphrase for the encryption of this file (access passphrase). 
    * There are no controls on the quality of the passphrase value used.
    * (Note that the empty passphrase is allowed.)  
    * 
    * @param userpass <code>PwsPassphrase</code>, the access passphrase to be used 
    *        on persistent states. Use <b>null</b> to clear
    */
   public synchronized void setPassphrase ( PwsPassphrase userpass )
   {
      ps = userpass == null ? null : (PwsPassphrase)userpass.clone();
      setModified();
      Log.debug( 2, "file passphrase modified to" + idString + ps ); 
      fireFileEvent( PwsFileEvent.PASSPHRASE_ALTERED, null );
   }
   
   /**
    * Sets the marker for preserving an old version of the persistent state
    * when saving (previous content state). (Package internal use only.)
    * 
    * @param value <b>true</b> = preserve old version
    */
   void setPreserveOld ( boolean value )
   {
      preserveOld = value;
   }

   /** Whether there exists a complete persistent file definition for this instance. 
    * 
    * @return <b>true</b> if and only if there is an application adapter defined 
    *         and there is a filepath defined
    * @since 0-3-0
    */
   public boolean hasResource ()
   {
      return application != null & filePath != null;
   }

   /** Whether this file has the same persistent resource as the parameter file.
    *  
    * @param file file to compare
    * @return <b>true</b> if and only if <code>file</code> is not <b>null</b> and
    *         both compare objects have either no or identical persistent files
    * @since 0-3-0
    */ 
   public boolean equalResource ( PwsFile file )
   {
      if ( file == null )
         return false;
      
      return (!hasResource() && !file.hasResource()) ||
             ( hasResource() && file.hasResource() &&
             application.equals( file.application ) &&
             filePath.equals( file.filePath ) );
   }

   /**
    * The file format number of the data source
    * from which this file was read in or 0 if 
    * this file was not read in.
    * 
    * @return int file format version
    * @since 2-0-0
    */
   public int getSourceFormat ()
   {
      return sourceFormat;
   }

   /** Sets the file format version number of the data source
    * from which this file was read in. (Package internal)
    *  
    * @param format file format version
    * @since 2-0-0
    */
   void setSourceFormat ( int format )
   {
      this.sourceFormat = format;
      this.fileVersionMajor = format;
   }

   /** Returns the operational header field list of this file. 
    * Use the returned object to perform your header field
    * operations. 
    * (This list is always present but will be saved to a
    * persistent state only in file format version V3.)
    * 
    * @return <code>HeaderFieldList</code>
    * @since 2-0-0
    */
   public HeaderFieldList getHeaderFields ()
   {
      return headerFields;
   }
   
   /** Returns a list of recently used entries, represented by their
    * serialised UUID values (32 hex char), separated by a ";" char.
    *  
    * @return String or <b>null</b> if this list is empty
    */
   public String getRecentUsedEntries ()
   {
      
      String hstr, uid, result = null;
      int num, i, index;
      
      // get the header field value according to PWS format def 3.10
      PwsRawField raw = 
            getHeaderFields().getField( PwsFileHeaderV3.RECENT_ENTRIES_TYPE );

      // interpret header value to fit our more process friendly formatting  
      if ( raw != null )
      {
         hstr = raw.getString( "ASCII" );
         Log.debug( 10, "(PwsFile.getRecentUsedEntries) obtained header value: ".concat( hstr ) );
         if ( hstr.length() > 2 )
         try {
            num = Integer.parseInt( hstr.substring( 0, 2 ), 16 );
            for ( i = 0; i < num; i++ )
            {
               index = i*32+2;
               uid = hstr.substring( index, index+32 );
               result = result == null ? uid : result + ";" + uid; 
            }
         } 
         catch ( Exception e ) 
         { e.printStackTrace(); }
      }
      Log.debug( 10, "(PwsFile.getRecentUsedEntries) returning with UUID list: " + result );
      return result;
   }

   /**
    * Sets the header field for "Recently Used Entries" after a programmatic
    * formatting using 32 char hex serialised UUID values for each entry,
    * separated by a ";" char in the list. 
    * 
    * @param value String formatted UUID list (may be <b>null</b>)
    */
   public void setRecentUsedEntries ( String value )
   {
      PwsRawField field;
      String hstr, va[];
      
      Log.log( 10, "(PwsFile.setRecentUsedEntries) enter with param == [" + value + "]");
      
      // construct value for external PWS format 3.10
      hstr = "";
      if ( value != null )
      {
         va = value.split( ";" );
         for ( int i = 0; i < va.length; i++  )
         {
            hstr += va[i];
         }
         hstr = Util.byteToHex( va.length ).concat( hstr );
      }
      
      try
      {
         field = new PwsRawField( PwsFileHeaderV3.RECENT_ENTRIES_TYPE, 
               hstr.getBytes( "ASCII" ) );
         getHeaderFields().setField( field );
         Log.debug( 10, "(PwsFile.setRecentUsedEntries) setting header field value to: ".concat( hstr ));
      }
      catch ( UnsupportedEncodingException e )
      { e.printStackTrace(); }
   }
   
   /** Method to replace all existing header fields of this file
    * with the fields of the parameter list. (This effectively
    * comes as a shallow copy of the parameter list.)
    *   
    *  @param list <code>HeaderFieldList</code>, if <b>null</b> nothing happens
    *  @since 2-0-0
    */
   public void setHeaderFields ( HeaderFieldList list )
   {
      Iterator it ;
      PwsRawField fld;
      byte[] buf;
      boolean oldPause;

      if ( list == null )
         return;
      
      if ( Log.getDebugLevel() > 6 )
         Log.debug( 7, "(PwsFile) setHeaderFields(): " );

      oldPause = eventPause;
      eventPause = true;
      
      headerFields.clear();
      for ( it = list.iterator(); it.hasNext(); )
      {
         fld = (PwsRawField)it.next();
         headerFields.setField( fld );
         if ( Log.getDebugLevel() > 6 )
            Log.debug( 7, "    id=" + fld.type + "  data=" + Util.bytesToHex( fld.getData() ) );
      }
      
      // analyse file format if supplied
      fld = headerFields.getField( PwsFileHeaderV3.FILE_FORMAT_TYPE );
      if ( fld != null )
      {
         buf = fld.getData();
         if ( buf.length >= 2 )
         {
            fileVersionMajor = buf[1];
            fileVersionMinor = buf[0];
         }
      }
      
      eventPause = oldPause;
      contentModified();
   }
   
   /** Sets the checksum verification status for a V3 file.
    * @param ok boolean result of the checksum verification 
    *  @since 2-0-0
    */
   protected void setChecksumResult ( boolean ok )
   {
      checksumOK = ok;
   }

   /**
    * Whether the checksum of a V3 file has been verified OK during
    * loading of the persistent state. (True for V2 and V1 or new files.)
    * 
    * @return <b>true</b> if and only if this file is a V3 file AND 
    *         load checksum is verified OK
    *  @since 2-0-0
    */
   public boolean isChecksumVerified ()
   {
      return checksumOK;
   }

   /** Sets the amount of security caclulation loops 
    *  valid for the access shield of this database. 
    *  The parameter value will be corrected to comply 
    *  with minimum 2048 and maximum 4194304.  
    *  (The property "SecurityLoops" is only meaningful
    *  for V3 files.)
    *  
    * @param loops amount of calculation loops
    * @since 2-1-0
    */
   public void setSecurityLoops ( int loops )
   {
      int i;
      
      i = securityLoops;
      securityLoops = Math.max( SECURITY_ITERATIONS_MINIMUM, Math.min( SECURITY_ITERATIONS_MAXIMUM, loops ) );
      if ( securityLoops != i )
         contentModified();
   }
   
   /** Returns the amount of security caclulation loops 
    *  valid for the access shield of this database.
    *  (The property "SecurityLoops" is only meaningful
    *  for V3 files.)
    *  
    *  @since 2-1-0
    */   
   public int getSecurityLoops ()
   {
      return securityLoops;
   }
   
   /**
    * Renders a content signature value for this PWS file.
    * Returns a SHA-256 checksum which is a sum-up of all its records' signatures
    * plus all its header field values. 
    * This value is considered individual to an instance.
    * (It may be assumed - although there is no guarantee - that this value is identical 
    * over different releases of this software package and different sessions of a
    * program running this package.)
    * 
    * @return byte[] 32 byte signature value (SHA-256 digest) 
    * @since 2-1-0
    */
   public byte[] getSignature ()
   {
      SHA256 sha;
      Iterator it;
      
      sha = new SHA256();
      
      sha.update( super.getSignature() );
      for ( it = headerFields.iterator(); it.hasNext(); )
         sha.update( ((PwsRawField)it.next()).data );
      
      return sha.digest();
   }
   

   
// **************  INNER CLASSES  **************************+
   
   /**
    * This class is a descendant of HeaderFieldList which adds
    * functionality to set the file modified, including event
    * dispatching, upon content modification in the header list.
    * 
    * @since 2-1-0
    */
   
   private class PFHeaderFieldList extends HeaderFieldList
   {

      public void clearUnknownFields ()
      {
         int size;

         size = super.getUnknownFieldCount();
         super.clearUnknownFields();
         if ( size > 0 )
            contentModified();
      }

      public PwsRawField setField ( PwsRawField field )
      {
         PwsRawField f;
         
         f = super.setField( field );
         if ( !field.equals( f ) )
            contentModified();
         return f;
      }

      public void clear ()
      {
         int size;
         
         size = super.size();
         super.clear();
         if ( size > 0 )
            contentModified();
      }

      public PwsRawField removeField ( int type )
      {
         PwsRawField fld;
         
         if ( (fld = super.removeField( type )) != null )
            contentModified();
         return fld;
      }
   
   }
}
