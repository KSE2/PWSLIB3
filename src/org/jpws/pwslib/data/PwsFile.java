/*
 *  File: PwsFile.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 07.08.2005
 * 
 *  Copyright (c) 2005-2015 by Wolfgang Keller, Munich, Germany
 * 
 This program is copyright protected to the author(s) stated above. However, 
 you can use, redistribute and/or modify it for free under the terms of the 
 2-clause BSD-like license which is given in the document section of this 
 project.  

 This program is distributed in the hope that it will be useful, but WITHOUT
 ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 FOR A PARTICULAR PURPOSE. See the license for more details.
 */

package org.jpws.pwslib.data;

import java.awt.Dimension;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.Collection;
import java.util.Iterator;

import org.jpws.pwslib.crypto.SHA256;
import org.jpws.pwslib.exception.ApplicationFailureException;
import org.jpws.pwslib.exception.DuplicateEntryException;
import org.jpws.pwslib.exception.InvalidPassphraseException;
import org.jpws.pwslib.exception.PasswordSafeException;
import org.jpws.pwslib.global.Global;
import org.jpws.pwslib.global.Log;
import org.jpws.pwslib.global.UUID;
import org.jpws.pwslib.global.Util;
import org.jpws.pwslib.order.DefaultRecordWrapper;
import org.jpws.pwslib.persist.ApplicationAdapter;
import org.jpws.pwslib.persist.DefaultFilesystemAdapter;

/**
 *  Top level structure of this library to represent a <i>Password Safe</i> 
 *  (PWS) database file. It is both a container for a set of {@link PwsRecord} 
 *  and a device to communicate the persistent state with external media.
 *  
 *  <p>This class is an extension of a record list ({@link PwsRecordList}),
 * hence data of all records are kept in memory, eventually causing restrictions
 * on the amount of records that can be kept during a program session.  
 * This class deals with all definitions required to represent, create or handle
 * a "persistent state" (encrypted PWS file) of a record list on an external 
 * medium. In addition to the record list, it allows to define a set of up to 
 * 255 <b>"header fields"</b> which are data elements on a list generic level.
 * Just as with <code>PwsRecordList</code>, the methods of this class are not
 * synchronised.
 * 
 * <p><u>Persistent State</u> 
 * <p>The <b><i>persistent state</i></b> is defined, in the sense of all
 * required parameters for an IO-operation, by a quadruple: 
 * i) the IO-context (application adapter),
 * ii) the filename (filepath), 
 * iii) the access passphrase, 
 * and iv) the file format version. 
 * It is ensured that there are always valid settings for application adapter 
 * and file format. The default adapter is <code>Global.getStandardApplication()
 * </code>.
 * <p>Using {@link ApplicationAdapter} interface is a fairly abstract conception
 * to access peripheral media and allows to adapt the services of this class to
 * any user context. The full definition of a persistent state is however not 
 * mandatory to use an instance of <code>PwsFile</code>. 
 * 
 * <p><u>File IO:</u> 
 * <p>Persistent states (external file data) are accessed through data streams 
 * which are made available by application adapters. The handling of file-IO
 * and data formatting is done by class {@link PwsFileFactory}.  
 * To obtain an instance of this class from its persistent state, use the static
 * methods of class <code>PwsFileFactory</code> or the <code>loadFile()
 * </code> method of this class. To create a persistent state
 * use the <code>save()</code> or <code>saveCopy()</code> methods of this class 
 * when all required parameters for the persistent state are available.
 * If a loaded file was of a different format version, or some indication of 
 * potential data loss occurred during loading, the next save will make an 
 * attempt to preserve the existing file by adding a name extension ".old".
 *
 *  <p><u>File Formats</u>
 * <p>This class now supports reading and writing of all three historical, major 
 * file format versions of <i>Password Safe</i>. The following policy is adopted
 * concerning these formats. Files loaded from a persistent state feature the 
 * format version of the persistent state. 
 * New instances (not loaded) feature the latest available format version.
 * File saving produces an output format version as currently set in the 
 * <code>PwsFile</code> object. At any time the user can modify the file format
 * setting of an instance without restrictions. Downgrading a file version may,
 * however, result in loss of record data that is not supported in the older 
 * format.  
 *  
 * <p><u>Header Fields</u>
 * <p>Since PWS format version 3 a facility for up to 255 data fields, each of
 * free length and type, is supported by <code>PwsFile</code>.
 * This is a handy way of making file generic information available which may be
 * application specific. Through <code>getHeaderFields()</code> the user gets 
 * hold of a {@link HeaderFieldList} containing elements of type
 * {@link PwsRawField}. This list can be mined for and manipulated with data; 
 * however it will only be stored on a persistent state in file format V3.
 * There are several reserved data fields defined by PWS and JPWS. The user of
 * this library should not define proprietary fields in the range 0x00 .. 0x7F.
 *  
 * <p><u>User Options:</u>
 * <p>User options take the form of a text string and are now stored as an 
 * element of the header field list (field-ID is 
 * <code>PwsFileHeaderV3.JPWS_OPTIONS_TYPE</code>).
 * These options are reflected both into V3 and V2 files. For V2 files 
 * options also may contain the <i>PasswordSafe Preferences</i> (special options 
 * of the program PWS); for V3 files <i>PWS Preferences</i> are stored 
 * in a special header field and may be accessed by field-ID 
 * <code>PwsFileHeaderV3.PWS_PREFS_TYPE</code>.
 * 
 * <p><u>Universal Encoding:</u>
 * <p>As of file format version V3 all text data is stored in universal encoding
 * UTF-8. Previous formats may also refer to the current JVM default encoding. 
 * 
 * @see PwsFileFactory
 * @see ApplicationAdapter
 */
public class PwsFile extends PwsRecordList implements Cloneable
{
   /** Minimum number of security calculation loops for access key verification.
   */
   public static final int SECURITY_ITERATIONS_MINIMUM = 2048;

   /** Maximum number of security calculation loops for access key verification. 
   */
   public static final int SECURITY_ITERATIONS_MAXIMUM = 2048 * 2048 *100;
   
   /** 
    * The application adapter representing the context of this file's
    * persistent state
    */
   private ApplicationAdapter application;
   
   /** The fully qualified path to the file */
   private String		   filePath;

   /** The (persistent) file access passphrase */
   private PwsPassphrase   ps;

   /** PWS format version number (major figure) for this file */
   private int             formatVersionMajor = Global.FILEVERSION_LATEST_MAJOR;

   /** PWS format version number (minor figure)  for this file */
   private int             formatVersionMinor = Global.FILEVERSION_LATEST_MINOR;

   /** PWS format version number of the load source */
   private int             sourceFormat;
   
   /** Number of calculation loops during file access authentication */
   private int             securityLoops = SECURITY_ITERATIONS_MINIMUM;
   
   /** A time-stamp for this file; normally meant to reflect the external 
    *  state time */
   private long timeStamp;
   
   /** Whether the V3 file trailing checksum was verified OK;
    * (true for V2 and V1 files) 
    */
   private boolean         checksumOK = true;

   /** A list of raw-fields representing the file's header fields;
    * (feature of the V3 file format) 
    */
   private HeaderFieldList     headerFields = new PFHeaderFieldList(); 
   
   /**
    * Flag indicating whether an attempt should be made to preserve the 
    * current persistent file state by renaming it as ".old" copy 
    * during next save operation.
    */
   private boolean         preserveOld;

   
	/**
	 * Constructs a new, empty PWS database for the standard
     * IO-context (by default the local file system). This file has a void 
     * definition of the persistent state; filepath and passphrase 
     * have to be set up before this file can be saved. 
     * 
     * @throws IllegalStateException if no global standard application is 
     *         available
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
     * Duplicate records in the array lead to an exception thrown; no check for 
     * record validity is performed.
     * <p>The resulting instance has no persistent state definition and no
     * passphrase assigned! 
     * 
     * @param recs array of <code>DefaultRecordWrapper</code> objects;
     *        may be <b>null</b>
     * @throws DuplicateEntryException 
     */
    public PwsFile( DefaultRecordWrapper[] recs ) throws DuplicateEntryException
    {
       super( recs );
       initBasic();

       Log.log( 2, "(PwsFile) new PwsFile (with record set): ID = " + fileID );
    }  // constructor

    /**
     * Constructs a new PWS database with an initial
     * record content as given by the parameter record collection. 
     * Duplicate records in the collection lead to an exception thrown; no check
     * for record validity is performed.
     * <p>The resulting instance has no persistent state definition and no
     * passphrase assigned! 
     * 
     * @param recs <code>Collection</code> of <code>PwsRecord</code>,
     *        may be <b>null</b>
     * @throws DuplicateEntryException 
     */
    public PwsFile( Collection<PwsRecord> recs ) throws DuplicateEntryException
    {
       super( recs );
       initBasic();

       Log.log( 2, "(PwsFile) new PwsFile (with record set): ID = " + fileID );
    }  // constructor

    /**
     * Constructs a new PWS database with an initial
     * record content as given by the parameter record array. 
     * Duplicate records in the array lead to an exception thrown; no check
     * for record validity is performed.
     * <p>The resulting instance has no persistent state definition and no
     * passphrase assigned! 
     * 
     * @param recs array of <code>PwsRecord</code>, may be <b>null</b>
     * @throws DuplicateEntryException 
     */
    public PwsFile( PwsRecord[] recs ) throws DuplicateEntryException
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
    *        the persistent state of this file; may be <b>null</b> for the 
    *        global standard application
    * @param filepath String filepath specification for the persistent state
    * @param userpass <code>PwsPassphrase</code> passphrase used to encrypt 
    *        the file
    * 
    * @throws IllegalArgumentException if a parameter is void
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
    * all required references for an external persistent state.
    * 
    * @param file <code>ContextFile</code> the file definition 
    *        used to save the persistent state of this file
    * @param userpass <code>PwsPassphrase</code> passphrase used to encrypt 
    *        the file
    * 
    * @throws IllegalArgumentException if a parameter is void
    */
   public PwsFile ( ContextFile file, PwsPassphrase userpass )
   {
      super();
      if ( file == null )
          throw new IllegalArgumentException( "file parameter missing" );
      
      initFull(file.getAdapter(), file.getFilepath(), userpass);
   } // constructor

   /**
    * Constructs a fully defined, empty PWS database in
    * the standard application IO-context (by default the local file system).
    * 
    * @param filepath String filepath specification for the persistent state
    * @param userpass <code>PwsPassphrase</code> object defining the access
    *        passphrase used to encrypt the file
    * 
    * @throws IllegalArgumentException if any parameter is void
    * @throws IllegalStateException if no global standard application adapter 
    *         is available
    */
   public PwsFile ( String filepath, PwsPassphrase userpass )
   {
	  this(null, filepath, userpass);
   }  // constructor

   private void initBasic ()
   {
      // install global default application adapter
      if ( (application = Global.getStandardApplication()) == null )
         throw new IllegalStateException( "no standard application available" );
      
      // take over UUID from super class into header fields
      headerFields.setField(new PwsRawField(1, getUUID().getBytes()));
      resetModified();
   }
   
   private void initFull ( ApplicationAdapter appl,
                           String filepath, 
                           PwsPassphrase userpass )
   {
      if ( appl == null ) {
    	  appl = Global.getStandardApplication();
          if ( appl == null ) 
              throw new IllegalStateException( "no standard application available" );
      }
      if ( filepath == null || filepath.isEmpty() )
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
    * Registered file listeners are removed from the clone, UUID is the same.
    * 
    * @return Object (type <code>PwsFile</code>)
    */
   @Override
   public Object clone ()
   {
      PwsFile file = (PwsFile)super.clone();
      if ( file == null ) return null;
      
      file.headerFields = (HeaderFieldList) headerFields.clone();

      Log.log( 2, "(PwsFile) new PwsFile (clone of " + idString + 
               "): ID = " + file.idString );
      return file;
   }

   /** Returns a copy of this file with a new UUID identifier. (This works 
    * identical to clone except for a new identifier and the suiting return 
    * type.)
    * 
    * @return <code>PwsFile</code>
    */
   @Override
   public PwsFile copy () 
   {
	   return (PwsFile)super.copy();
   }
   
   /**
    * This method replaces entire content of this file, including all settings,
    * by the contents of the parameter file. Works as a shallow clone of the 
    * record list and shares identity with the parameter file.
    *   
    * @param f <code>PwsFile</code> new content for this file
    */
   public void replaceFrom ( PwsFile f )
   {
      super.replaceFrom( f );
      application = f.application;
      filePath = f.filePath;
      timeStamp = f.timeStamp;
      checksumOK = f.checksumOK;
      preserveOld = f.preserveOld;
      formatVersionMajor = f.formatVersionMajor;
      formatVersionMinor = f.formatVersionMinor;
      securityLoops = f.securityLoops;
      sourceFormat = f.sourceFormat;
      ps = f.ps;

      boolean p = getEventPause();
      setEventPause( true );
      headerFields.clear();
      for (Iterator<PwsRawField> it = f.headerFields.iterator(); it.hasNext();) {
         headerFields.setField( it.next() );
      }
      setEventPause( p );
      modified = f.modified;
   }
   
	/**
    * Returns the file path of the persistent state definition of this file or 
    * <b>null</b> if it is undefined.
    * 
    * @return String file path or null
    */
   public final String getFilePath()
   {
      return filePath;
   }

   /**
    * Returns the file name (last path element) of the persistent state 
    * definition of this file or <b>null</b> if it is undefined.
    * 
    * @return String file name or null
    */
   public final String getFileName()
   {
      return filePath == null ? null : new File( filePath ).getName();
   }

	/**
	 * Returns the major format version number for this file. The default 
     * of a new file is <code>Global.FILEVERSION_LATEST_MAJOR</code>.
	 * 
	 * @return int format version number
	 */
	public final int getFormatVersion()
   {
      return formatVersionMajor;
   }

	/**
	 * Returns the format information for this file, containing both major
	 * and minor version numbers.
	 * 
	 * @return <code>Dimension</code>, width = major, 
	 *         height = minor version number 
	 */
	public final Dimension getFileFormat ()
	{
	   return new Dimension(formatVersionMajor, formatVersionMinor);
	}
	
    /**
     * Returns the activated character set used to encode text strings on the 
     * persistent state. (The charset is "Utf-8" for V3 file format (fixum) or 
     * for V2 format if "B 24 1" is present in user options. It is the VM 
     * default character set otherwise.)
     *  
     * @return String charset name
     */ 
    public String getCharset ()
    {
       return formatVersionMajor > Global.FILEVERSION_2 || 
              (formatVersionMajor == Global.FILEVERSION_2 && getUserOptions()
              .indexOf("B 24 1") > -1) ? "UTF-8" : Global.getDefaultCharset();
    }
    
   /**
    * Sets the format version number for this file. The value determines
    * the technical file format of the persistent state of this file.
    * If the value is out of range, the latest format version is
    * assumed.
    * 
    * @param value int file format version (use one of the values defined 
    *              in class <code>Global</code>) or 0 for latest format
    */
   public void setFormatVersion ( int value )
   {
      if ( value < 1 | value > Global.FILEVERSION_3 ) {
         value = Global.FILEVERSION_LATEST_MAJOR;
      }

      if ( value != formatVersionMajor ) {
         // assign new format
         int oldVersion = formatVersionMajor;
         formatVersionMajor = value;
         
         // if upgrade from earlier version then remove unknown fields
         if ( oldVersion < formatVersionMajor ) {
            clearUnknownFields();
         }
         
         // if switch to V3 format AND there is no UUID defined in header fields
         // then store UUID from PwsRecordList into relevant header field
         if ( value == Global.FILEVERSION_3 && 
              headerFields.getField( PwsFileHeaderV3.FILE_UUID_TYPE ) == null ) {
            headerFields.setField( new PwsRawField( PwsFileHeaderV3.FILE_UUID_TYPE, 
                  getUUID().getBytes() ));
         }

         // inform object and listeners of modification
         contentModified();
      }
   }

	/**
	 * Returns the encryption passphrase used on this file (access passphrase).
	 * 
	 * @return <code>PwsPassphrase</code> copy of the file's access passphrase 
	 *         or <b>null</b> if it is not defined
	 */
	public final PwsPassphrase getPassphrase()
	{
		return ps == null ? null : (PwsPassphrase)ps.clone();
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
    * persistent state definition (application and filepath).
    * 
    * @return <code>ContextFile</code> or <b>null</b> if unavailable
    */
   public ContextFile getContextFile ()
   {
      return hasResource() ? new ContextFile(getApplication(), getFilePath()) : null;
   }

   /**
    * Returns the last modification time of the persistent state of this 
    * file. This queries to external medium.
    *  
    * @return last long modification time (milliseconds) or 0 if there exists 
    *         no persistent state or this information is not available
    * @throws IOException
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
    */
   public long getUnknownFieldSize ()
   {
      return super.getUnknownFieldSize( formatVersionMajor ) 
             + headerFields.getUnknownFieldSize( formatVersionMajor );
   }

   /**
    * Returns the number of data fields which are kept as non-canonical 
    * in this list of records.
    * 
    * @return int number of non-canonical records
    */
   @Override
   public int getUnknownFieldCount ()
   {
      return super.getUnknownFieldCount() + headerFields.getUnknownFieldCount();
   }

   /** Clears away all non-canonical fields from this database, including 
    * unknown header fields. 
    */
   @Override
   public void clearUnknownFields ()
   {
      super.clearUnknownFields();
      
      // clear UKF in headerfield list
      int ctrl = headerFields.size();
      headerFields.clearUnknownFields();
      if ( headerFields.size() != ctrl ) {
         contentModified();
      }
   }
   
   /**
    * Returns the size of the data block required to store the content of
    * this database on a persistent state. (This takes into respect the 
    * general file formating rules of a PWS file of the specified format.) 
    * This is a relatively expensive operation as it walks through analysing 
    * all records with each call.
    * 
    * @param format int file format version of the projected persistent state
    * @return long required (blocked) data size
    */
   public long getBlockedDataSize ( int format )
   {
      // sum-up of record content 
      String charset = getCharset();
      long sum = super.getBlockedDataSize(format, charset);

      // constant file overhead
      switch ( format ) {
      case Global.FILEVERSION_1:
         sum += 56;
         break;
      case Global.FILEVERSION_2:
         sum += 56 + 12 * 8;
         try { 
        	 sum += PwsRawField.pwsFieldBlockSize( getUserOptions()
        			.getBytes( charset ).length, format );
         } catch ( UnsupportedEncodingException e ) {
         }
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
    * MODIFIED flag is reset to <b>false</b>. This method does 
    * nothing if the MODIFIED flag is found to be <b>false</b>.
    * <p><small>The persistent state of a file is defined by 
    * application adapter, filepath and access passphrase.</small>
	 * 
    * @throws IllegalStateException if the required parameters for the
    *         persistent state are not set up  
    * @throws IOException if an IO-error occurs
    * @throws ApplicationFailureException if the IO-context fails to render
    *         an output stream 
	 */
	public void save() throws IOException, ApplicationFailureException
	{
       if ( isModified() ) {
          if ( application == null | filePath == null | ps == null )
             throw new IllegalStateException( "persistent state parameters not set" );
         
          // rename existing file to "*.old" (conditional)
          if ( (sourceFormat != 0 & formatVersionMajor != sourceFormat) 
        	   | preserveOld ) {
             try {
                // preserve a copy of the previous version of the file
                String hstr = filePath + ".old";
               
                Log.log( 5, "(PwsFile) renaming previous file to : " + hstr ); 
                if ( application.renameFile( filePath, hstr ) ) {
                   Log.debug( 2, "--- renamed " + filePath + " to: " + hstr );
                } else {
                   Log.error( 2, "*** unable to rename file " + filePath +
                         ", target: " + hstr );
                }
             } catch ( Exception e ) {
             }
          }

          // save content of this file
          String hstr = idString + extFileRef(application, filePath);
          Log.log( 4, "(PwsFile) saving file to" + hstr ); 

          PwsFileFactory.saveFile( internalIterator(), application, filePath, ps, headerFields, 
                securityLoops, formatVersionMajor );
   	      timeStamp = application.getModifiedTime(filePath);
   	      resetModified();
          Log.log( 4, "(PwsFile) file save finished (before event dispatch), " + timeStamp);
         
          fireFileEvent( PwsFileEvent.LIST_SAVED, null );
          Log.debug( 2, "(PwsFile.save) file saved to: " + hstr ); 
       }
	}  // save

	/** Writes a persistent state of this file to the given output stream.
	 * There is no reset of the MODIFIED flag after execution.
	 * 
	 * @param output <code>OutputStream</code>
     * @throws IllegalStateException if the encryption passphrase is not set up
	 * @throws IOException if an IO-exception occurs
     * @throws NullPointerException if output is null  
	 */
	public void write ( OutputStream output ) throws IOException 
	{
        if ( ps == null )
            throw new IllegalStateException( "passphrase not set" );

        Log.log( 6, "(PwsFile) writing file to output stream" ); 
        PwsFileFactory.saveFile( internalIterator(), output, ps, headerFields, 
              securityLoops, formatVersionMajor );
        Log.log( 6, "(PwsFile) file written to output");
	}
	
	/** Reads and renders a <code>PwsFile</code> from an input data stream.
	 * 
	 * @param input <code>InputStream</code>
	 * @param ps <code>PwsPassphrase</code> encryption key
	 * @return <code>PwsFile</code>
     * @throws InvalidPassphraseException if the given passphrase is false
	 * @throws PasswordSafeException
	 * @throws IOException if an IO-error occcurs
     * @throws NullPointerException if any parameter is null 
	 */
	public static PwsFile read ( InputStream input, PwsPassphrase ps ) 
			throws IOException, PasswordSafeException 
	{
        Log.log( 6, "(PwsFile) reading a file from input stream" ); 
        PwsFile file = PwsFileFactory.loadFile( input, ps, 0 );
        Log.log( 6, "(PwsFile) file read from input stream");
		return file;
	}
	
   /**
    * Writes a copy of this file to the specified file of the specified medium, 
    * applying the same passphrase as is defined for this file.  
    * The copy will own a different UUID identifier.
    *
    * @param app ApplicationAdapter the application context in which the target
    *        file will be created;
    *        if <b>null</b> then the same application is referred to as is 
    *        defined for <b>this</b> file  
    * @param filepath String the file name specification for the target file
    * 
    * @return UUID the file identifier value of the copy or <n>null</b> if 
    *         unavailable
    * @throws IllegalArgumentException if <code>filepath</code> or the file
    *         passphrase are not defined
    * @throws IOException if an IO-error occurs
    * @throws ApplicationFailureException if the IO-context fails to render
    *         an output stream 
    */
   public UUID saveCopy( ContextFile targetFile ) 
         throws IOException, ApplicationFailureException
   {
      return saveCopy( targetFile, null, 0, new UUID() );
   }

   /**
    * Writes a copy of this file to the specified file of the specified medium, 
    * allowing to setup a different access passphrase for the copy. 
    * The copy will own a different UUID identifier.
    *
    * @param targetFile <code>ContextFile</code> file specification for the 
    *        copy target
    * @param pass PwsPassphrase an optional passphrase for the copy; if 
    *        <b>null</b> the passphrase of this file is used       
    * 
    * @return UUID the file identifier value of the copy or <n>null</b> if 
    *         unavailable
    * @throws IllegalArgumentException if <code>filepath</code> or the file
    *         passphrase are not defined
    * @throws IOException if an IO-error occurs
    * @throws ApplicationFailureException if the IO-context fails to render
    *         an output stream 
    */
   public UUID saveCopy( ContextFile targetFile, PwsPassphrase pass ) 
         throws IOException, ApplicationFailureException
   {
      return saveCopy( targetFile, pass, 0, new UUID() );
   }

   /**
    * Writes a copy of this file to the specified file of the specified medium, 
    * allowing to setup a different passphrase and a different file format 
    * version for the copy. 
    *
    * @param targetFile <code>ContextFile</code> file specification for the 
    *        copy target
    * @param pass PwsPassphrase an optional passphrase for the copy; if 
    *        <b>null</b> the passphrase of this file is used
    * @param format int the target file format version or 0 for this file's 
    *        format setting   
    * @param fileUUID <code>UUID</code> if not <b>null</b> the copy will assume
    *        this UUID value, otherwise keep the existing UUID; V3 only  
    * @return UUID the file identifier value of the saved file or <b>null</b> if
    *         unavailable
    * @throws IllegalArgumentException if <code>filepath</code> or the 
    *         passphrase are not defined
    * @throws IOException if an IO-error occurs
    * @throws ApplicationFailureException if the IO-context fails to render
    *         an output stream 
    */
   public UUID saveCopy( ContextFile targetFile, PwsPassphrase pass, 
		                 int format, UUID fileUUID ) 
         throws IOException, ApplicationFailureException
   {
      // some default constitutive values from original
      if ( pass == null )
         pass = ps;
      if ( format == 0 )
         format = formatVersionMajor;

      // we copy the headers to prevent update events striking through to the original
      // these events may occur here and deep down in PwsFileFactory
      // (don't use "clone()" here!)
      HeaderFieldList headers = new HeaderFieldList(headerFields);
      
      if ( format == Global.FILEVERSION_3 & fileUUID != null ) {
         // create new UUID value in header field of the copy
    	 PwsRawField field = new PwsRawField(1, fileUUID.getBytes()); 
         headers.setField( field ); 
      }
      
      // save copy in file factory
      Log.log( 2, "(PwsFile) saving a file copy to" + idString  + extFileRef(targetFile)); 
      UUID fid = PwsFileFactory.saveFile(iterator(), targetFile, pass, headers, 
    		     securityLoops, format);

      String hstr = fid != null ? fid.toHexString() : "void";
      Log.log( 2, "(PwsFile) copy done, target UUID = " + hstr ) ; 
      return fid;
   }

   @Override
   public void setUUID(UUID fileUUID) {
	  super.setUUID(fileUUID);
      headerFields.setField( new PwsRawField( 1, getUUID().getBytes() ) );
   }

/**
    * Returns a human info file path notation incorporating the IO-context name.
    * 
    * @param app <code>ApplicationAdapter</code> the application context 
	* @param filePath String the path for the file
	* @return String human readable info about context + file
    */
   protected String extFileRef ( ApplicationAdapter app, String filePath )
   {
      return "\"" + app.getName() + "\" -> " + filePath;
   }
   
   /**
    * Returns a human info file path notation incorporating the IO-context name.
    * 
    * @param file <code>ContextFile</code> file 
	* @return String human readable info about context + file
    */
   protected String extFileRef ( ContextFile file )
   {
	   ApplicationAdapter app = file.getAdapter();
	   String filePath = file.getFilepath();
	   return extFileRef( app, filePath );
   }
   
   /**
	 * Sets the name of the external file that contains the persistent state of
	 * this file. Use <b>null</b> to clear.
	 * 
	 * @param path String the name for the file, may be <b>null</b> but not
	 * empty
    * @throws IllegalArgumentException is the parameter value is empty
	 */
	public void setFilePath( String path )
	{
      if ( path != null && path.isEmpty() )
         throw new IllegalArgumentException("empty filename");
      
	  filePath = path;
      setModified();
      Log.debug( 2, "(PwsFile) file path modified to" + idString  + filePath ); 
      fireFileEvent( PwsFileEvent.TARGET_ALTERED, null );
   }


   /**
    * Sets the application adapter (IO-context) for this file.
    * 
    * @param app <code>ApplicationAdapter</code> the new application context 
    *            valid for this file
    * @throws NullPointerException if the parameter is null
    */
   public void setApplication( ApplicationAdapter app )
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
    * 
    * @param f <code>ContextFile</code> external file definition
    */
   public void setPersistentFile ( ContextFile f )
   {
      if ( f == null ) {
          filePath = null;
      } else {
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
    * data field. The PWS specific preferences of a V3 file can be obtained by 
    * <code>getHeaderFields().getField(PwsFileHeaderV3.PWS_PREFS_TYPE).getString("utf-8")</code>.
    * V1 format does not support an option string.</small>  
    *  
    * @return String with user options; empty string if undefined 
    */
   public String getUserOptions ()
   {
      PwsRawField raw = headerFields.getField( PwsFileHeaderV3.JPWS_OPTIONS_TYPE );
      String options = raw == null ? "" : raw.getString( "utf-8" );  

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
   public void setUserOptions ( String options )
   {
      if ( options == null ) {
         options = "";
      }

      Log.log( 7, "(PwsFile) setting user options = \"" + options + "\"" );
//      Log.debug( 7, "(PwsFile.setUserOptions) old user options = \"" + getUserOptions() + "\"" );
      if ( !options.equals( getUserOptions() ) ) {
         setModified();
         try{ 
            headerFields.setField( new PwsRawField( PwsFileHeaderV3.JPWS_OPTIONS_TYPE, options.getBytes("utf-8") )); 
            contentModified();
         } catch ( UnsupportedEncodingException e ) {
         }
      }
   }
   
   /**
    * Sets the user passphrase for the encryption of this file (access 
    * passphrase).There are no controls on the quality of the passphrase value 
    * used. The empty passphrase is allowed.  
    * 
    * @param userpass <code>PwsPassphrase</code>, the access passphrase to be 
    *        used on persistent states. Use <b>null</b> to clear
    */
   public void setPassphrase ( PwsPassphrase userpass )
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
    * @param boolean value <b>true</b> = preserve old version
    */
   void setPreserveOld ( boolean value )
   {
      preserveOld = value;
   }

   /** Whether there exists a complete persistent file definition for this 
    * instance. 
    * 
    * @return boolean <b>true</b> if and only if there is an application adapter 
    *         and a filepath defined
    */
   public boolean hasResource ()
   {
      return application != null & filePath != null;
   }

   /** Whether this file has the same persistent resource as the parameter file.
    *  
    * @param file <code>PwsFile</code> file to compare
    * @return boolean <b>true</b> if and only if <code>file</code> is not 
    * 		  <b>null</b> and both compare objects have either no or identical 
    * 		  persistent files
    */ 
   public boolean equalResource ( PwsFile file )
   {
      if ( file == null ) return false;
      
      return (!hasResource() && !file.hasResource()) ||
             ( hasResource() && file.hasResource() &&
             application.equals( file.application ) &&
             filePath.equals( file.filePath ) );
   }

   /**
    * The file format number of the data source from which this file was read 
    * in, or 0 if this file was not read in.
    * 
    * @return int file format version
    */
   public int getSourceFormat ()
   {
      return sourceFormat;
   }

   /** Sets the file format version number of the data source
    * from which this file was read in. (Package internal)
    *  
    * @param format int file format version
    */
   void setSourceFormat ( int format )
   {
      this.sourceFormat = format;
      this.formatVersionMajor = format;
   }

   /** Returns the operational header field list of this file. 
    * Use the returned object to perform your header field operations. 
    * (This list is always present but will be saved to a
    * persistent state only in file format version V3.)
    * 
    * @return <code>HeaderFieldList</code>
    */
   public HeaderFieldList getHeaderFields ()
   {
      return headerFields;
   }
   
   /** Returns a list of recently used entries, represented by their
    * serialised UUID values (32 hex char), separated by a ";" char
    * or <b>null</b> if this value is not available.
    *  
    * @return String or <b>null</b>
    */
   public String getRecentUsedEntries ()
   {
      String hstr, uid, result = null;
      int num, i, index;
      
      // get the header field value according to PWS format def 3.10
      PwsRawField raw = 
            getHeaderFields().getField( PwsFileHeaderV3.RECENT_ENTRIES_TYPE );

      // transform header value to our more process friendly formatting  
      if ( raw != null ) {
         hstr = raw.getString( "ASCII" );
         Log.debug(10, "(PwsFile.getRecentUsedEntries) obtained header value: "
        		 .concat(hstr));
         if ( hstr.length() > 2 )
         try {
            num = Integer.parseInt( hstr.substring(0, 2), 16 );
            for ( i = 0; i < num; i++ ) {
               index = i*32+2;
               uid = hstr.substring( index, index+32 );
               result = result == null ? uid : result + ";" + uid; 
            }
         } catch ( Exception e ) { 
        	 e.printStackTrace(); 
         }
      }
      Log.debug( 10, "(PwsFile.getRecentUsedEntries) returning with UUID list: " + result);
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
      Log.log( 10, "(PwsFile.setRecentUsedEntries) enter with param == [" + value + "]");
      
      // construct value for external PWS format 3.10
      String hstr = "";
      if ( value != null ) {
         String[] va = value.split( ";" );
         for ( String s : va ) {
            hstr += s;
         }
         hstr = Util.byteToHex( va.length ).concat( hstr );
      }
      
      // create a new field and add to header field list
      try {
    	  PwsRawField field = new PwsRawField( PwsFileHeaderV3.RECENT_ENTRIES_TYPE, 
                 hstr.getBytes( "ASCII" ) );
         getHeaderFields().setField( field );
         Log.debug( 10, "(PwsFile.setRecentUsedEntries) setting header field value to: ".concat( hstr ));

      } catch ( UnsupportedEncodingException e ) { 
    	  e.printStackTrace(); 
  	  }
   }
   
   /** Method to replace all existing header fields of this file
    * with the fields of the parameter list. 
    * Does nothing if <code>list</code> is <b>null</b>.
    *   
    *  @param list <code>HeaderFieldList</code>, may be null
    */
   public void setHeaderFields ( HeaderFieldList list )
   {
      if ( list == null ) return;
      
      if ( Log.getDebugLevel() > 6 )
         Log.debug( 7, "(PwsFile.setHeaderFields) - list cleared - new entries:" );

      // avoid event dispatching
      boolean oldPause = eventPause;
      eventPause = true;
      
      // take over parameter list values
      headerFields.clear();
      for ( Iterator<PwsRawField> it = list.iterator(); it.hasNext(); ) {
    	 PwsRawField fld = it.next();
         headerFields.setField( fld );
         if ( Log.getDebugLevel() > 6 )
            Log.debug( 7, "    id=" + fld.type + "  data=" + Util.bytesToHex( fld.getData() ) );
      }
      
      // update file format property if supplied
      PwsRawField fld = headerFields.getField( PwsFileHeaderV3.FILE_FORMAT_TYPE );
      if ( fld != null ) {
    	 byte[] buf = fld.getData();
         if ( buf.length >= 2 ) {
            formatVersionMajor = buf[1];
            formatVersionMinor = buf[0];
         }
      }
      
      // resume event dispatching (old state)
      eventPause = oldPause;
      contentModified();
   }
   
   /** Sets the checksum verification status. (This is normally only
    * applicable for a V3 file.)
    * 
    * @param ok boolean result of the checksum verification 
    */
   protected void setChecksumResult ( boolean ok )
   {
      checksumOK = ok;
   }

   /**
    * Whether the checksum of this file has been set to "verified OK".
    * (True by default)
    * 
    * @return boolean true == checksum verified
    */
   public boolean isChecksumVerified ()
   {
      return checksumOK;
   }

   /** Sets the amount of security calculation loops valid for the access 
    * shield of this database. The parameter value will be corrected to assume 
    * a minimum of 2048 and maximum of 4194304.  
    * (The property "SecurityLoops" is only meaningful for V3 files.)
    *  
    * @param loops int amount of calculation loops
    */
   public void setSecurityLoops ( int loops )
   {
      int i = securityLoops;
      securityLoops = Math.max( SECURITY_ITERATIONS_MINIMUM, 
    		  Math.min( SECURITY_ITERATIONS_MAXIMUM, loops ) );
      if ( securityLoops != i ) {
         contentModified();
      }
   }
   
   /** Returns the amount of security calculation loops 
    *  valid for the access shield of this database.
    *  (The property "SecurityLoops" is only meaningful
    *  for V3 files.)
    *  
    *  @return int security loops  
    */   
   public int getSecurityLoops ()
   {
      return securityLoops;
   }
   
   /**
    * Renders a content signature value for this PWS file.
    * Returns a SHA-256 checksum which is the sum-up of all its records' 
    * signatures plus all its header field values. 
    * <p><small>It may not be assumed that this value is identical over 
    * different releases of this software package, however it is expected to be
    * identical over different program sessions running the same package.
    * </small>
    * 
    * @return byte[] 32 byte signature value (SHA-256 digest) 
    */
   @Override
   public byte[] getSignature () {
      SHA256 sha = new SHA256();
      sha.update( super.getSignature() );
      for ( Iterator<PwsRawField> it = headerFields.iterator(); it.hasNext(); ) {
         sha.update( it.next().getCrc() );
      }
      return sha.digest();
   }
   
   /**
    * Renders a data content signature value for this PWS file.
    * "Data content" is defined as the ordered set of records contained in this
    * file. Returns a SHA-256 checksum which is the sum-up of all records' 
    * signatures. 
    * <p><small>It may not be assumed that this value is identical over 
    * different releases of this software package, however, it is expected to be
    * identical over different program sessions running the same package.
    * </small>
    * 
    * @return byte[] 32 byte signature value (SHA-256 digest) 
    */
   public byte[] getDataSignature () {
      return super.getSignature();
   }
   
   /** Returns the logical database name if it is defined, <b>null</b>
    *  otherwise. This name is an element of the file's header fields.
    *  
    *  @return logical database name or <b>null</b> if undefined
    */
   public String getDatabaseName () {
      // use header field for logical name 
	  PwsRawField fld = getHeaderFields().getField( PwsFileHeaderV3.FILE_NAME_TYPE );
      return fld == null ? null : fld.getString( "utf-8" );
   }

   /**
    * Loads a PWS file of any format from the local file system.
    * For other sets of parameters see the <code>PwsFileFactory</code> class!
    * 
    * @param file <code>File</code> file to open
    * @param passphrase <code>PwsPassphrase</code> file access passphrase
    * 
    * @return the opened, fully operable <code>PwsFile</code> object 
    * 
    * @throws NullPointerException if any parameter is null 
    * @throws FileNotFoundException if the specified file was not found or
    *         access was denied
    * @throws InvalidPassphraseException if file access could not be verified
    * @throws PasswordSafeException if a file format error occurs
    * @throws IOException if an IO-error occurred
    */
   public static PwsFile loadFile( File file, PwsPassphrase passphrase )
		   	throws IOException, PasswordSafeException  {
	   try {
		   return PwsFileFactory.loadFile( DefaultFilesystemAdapter.get(), 
    		      file.getAbsolutePath(), passphrase, 0 );
	   } catch (IllegalArgumentException e) {
		   throw new FileNotFoundException();
	   }
   }
   
   
// **************  INNER CLASSES  **************************+
   
   /**
    * This class is a descendant of <code>HeaderFieldList</code> which adds
    * functionality to set the file modified, including event
    * dispatching, upon content modification in the header list.
    */
   
   private class PFHeaderFieldList extends HeaderFieldList
   {
      @Override
	  public void clearUnknownFields () {
         int size = super.getUnknownFieldCount();
         super.clearUnknownFields();
         if ( size > 0 )
            contentModified();
      }

      @Override
      public PwsRawField setField ( PwsRawField field ) {
         PwsRawField f = super.setField( field );
         if ( f == null || field.getCrc() != f.getCrc() ) {
            contentModified();
//            Log.log(10, "(PFHeaderFieldList.setField) ----- content modified!"); 
         }
         return f;
      }

      @Override
	  public void clear () {
         int size = super.size();
         super.clear();
         if ( size > 0 ) {
            contentModified();
         }
      }

      @Override
      public PwsRawField removeField ( int type ) {
         PwsRawField fld = super.removeField( type );
         if ( (fld) != null ) {
            contentModified();
         }
         return fld;
      }
   }

/** Returns the time-stamp for the external data state of this file. This is a
 * procedural datum and not element of the stored file. PWSLIB sets this value
 * when a file instance is loaded from or saved to the external state. 
 * 
 * @return long time
 */
public long getTimeStamp() {
	return timeStamp;
}

public void setTimeStamp (long timeStamp) {
	this.timeStamp = timeStamp;
}
}
