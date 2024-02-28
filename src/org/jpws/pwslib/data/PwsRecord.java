
/*
 *  File: PwsRecord.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 11.08.2004
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

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.IllegalCharsetNameException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.zip.CRC32;

import javax.swing.KeyStroke;

import org.jpws.pwslib.exception.InvalidPassphrasePolicy;
import org.jpws.pwslib.global.Global;
import org.jpws.pwslib.global.UUID;

import kse.utilclass.misc.SHA256;
import kse.utilclass.misc.Util;
import kse.utilclass.misc.Log;

/**
 * This class is a container for data fields belonging to a <i>Password Safe</i>
 * database entry. The set refers to a canon of field definitions given by the 
 * <i>Password Safe</i> persistent file description. The file format 
 * version this class implements is 3.13 (decimal). The following fields of 
 * the description are NOT available in this interface (although they are 
 * preserved when loaded from other applications): Double-Click-Action, 
 * Shift-Double-Click-Action, Run-Command. 
 * 
 * <p>A record-ID - a {@link org.jpws.pwslib.global.UUID} object - holds 
 * an immutable universal value and is by design always existent on a 
 * <code>PwsRecord</code>.
 * A minimum set of fields must be assigned non-empty for a record
 * in order to qualify for property "VALID" (e.g. could be made required for a
 * record list). These fields are: <b>TITLE</b> and <b>PASSWORD</b>.
 * 
 * <p>Instances of this class can be added to and updated at  
 * {@link PwsRecordList} or {@link PwsFile} objects. Any iterator over 
 * type <code>PwsRecord</code> can be used to create a persistent 
 * <i>Password Safe</i> file, e.g. on external media, by calling the save 
 * methods of <code>PwsFileFactory</code>.
 * 
 * <p><u>Non-Canonical Fields</u> 
 * <p>Field types outside of the canon are supported in various ways. 
 * <br>A) Non-canonical fields coming from other applications via persistent 
 * state are tolerated and stored back to file when a record is saved. 
 * <br>B) An application may utilise <b>Extra Fields</b> (one field value per 
 * type) by use of methods <code>setExtraField()</code> and 
 * <code>getExtraField()</code>. These fields also become part of the persistent
 * state in a well-defined way and should be conserved in other applications
 * unless they share conflicting type values. It is recommended private
 * applications do not claim field type numbers below 128.
 * 
 * <p><u>Transient Properties</u>
 * <p>The record property <b>"IMPORT-STATUS"</b> can be set by the user or 
 * is automatically set through <code>PwsRecordList.merge()</code>. It is purely 
 * informative about which records have been merged and not reflected into the
 * persistent state. 
 * 
 * <p><u>Conventions:</u>
 * <p><b>Normalised Group Names</b>. Group names, as values of the record field 
 * GROUP, may contain any sequence of valid elementary names (text) separated by 
 * a "." character. No "." character is permitted at the beginning or end of the
 * value. No empty elementary name is permitted ("..").  The "." character 
 * always has the meaning of separating group hierarchy levels and can not be a 
 * part of an elementary name. 
 * 
 * @see PwsFileFactory
 *
 */
public class PwsRecord implements Cloneable
{
   /** Import status value indicating that this record was added by the 
    * <code>merge()</code> method of a <code>PwsRecordList</code>.
    */
   public static final int IMPORTED = 1;
   
   /** Import status value indicating that this record was added by the 
    * <code>merge()</code> method of a <code>PwsRecordList</code> by overwriting
    * an existing record.
    */
   public static final int IMPORTED_CONFLICT = 2;

   /** General purpose constant for an empty iterator of raw-fields.
    */
   private static final Iterator<PwsRawField> emptyFieldIterator 
    						= new ArrayList<PwsRawField>().iterator();
   
   /** Stores fields whose identity is non-canonical (as known to this library). 
    * This includes fields that may have been generated 
    * by other applications or fields added through the "setExtraField()" method.
    */
   private RawFieldList     otherValues;
   
   // basic fields
   private UUID             recordID;
   private String           group;
   private String           title;
   private PwsPassphrase    username;
   private PwsPassphrase    notes;
   private PwsPassphrase    password;
   private PwsPassphrasePolicy  passPolicy;
   
   // V3 specific fields
   private PwsPassphrase    history;
   private PwsPassphrase    url;
   private PwsPassphrase    email;
   private KeyStroke        keyboardShortcut;
   private String           autotype;
   private String           passPolicyName;
   private int              expiryInterval;
   private boolean          protectedEntry;
   
   // unused V3 fields
   PwsRawField              runCommand;
   PwsRawField              dclickAction;
   PwsRawField              shiftDclickAction;
   
   // time fields, values stored in "epoch" milliseconds
   private long             createTime;
   private long             passLifeTime;
   private long             passModTime;
   private long             accessTime;
   private long             modifyTime;
   
   // operational
   private int              importStatus;
   private boolean          initializing;

  
   
/**
 *  Creates a new PWS record with a new Record-ID (UUID). The ID is 
 *  automatically generated.  
 */
public PwsRecord () {
   recordID = new UUID();
   createTime = normalisedTime(System.currentTimeMillis());
   modifyTime = createTime;
   Log.log( 4, "(PwsRecord) new PwsRecord: ".concat(toString()) );
}

/**
 *  Creates a new PWS record with a new Record-ID (UUID) and the specified
 *  CREATETIME.   
 *  
 *  @param time long epoch time value (milliseconds)
 */
public PwsRecord ( long time ) {
   recordID = new UUID();
   createTime = normalisedTime(time);
   modifyTime = createTime;
   Log.log( 4, "(PwsRecord) new PwsRecord: time == " + time +", " + toString() );
}

/**
 *  Creates a new PWS record with the given Record-ID.
 *
 *  @param recID <code>UUID</code>
 *  @throws NullPointerException if the parameter is <b>null</b>  
 */
public PwsRecord ( UUID recID ) {
   if ( recID == null )
      throw new NullPointerException();
   
   recordID = recID;
   createTime = normalisedTime(System.currentTimeMillis());
   modifyTime = createTime;
   Log.log( 4, "(PwsRecord) new PwsRecord (param ID): ".concat(toString()) );
}

private long normalisedTime (long time) {
	return time / 1000 * 1000;
}

/** Makes a deep clone of this record; preserves UUID value. 
 * 
 * @return Object record clone (<code>PwsRecord</code>)
 */
   @Override
   public Object clone () {
      try { 
    	 PwsRecord rec = (PwsRecord)super.clone();

         // deep clone of unknown fields
    	 if ( otherValues != null ) {
	         rec.otherValues = new RawFieldList();
	         for (Iterator<PwsRawField> it = getUnknownFields(); it.hasNext(); ) {
	        	PwsRawField fld = it.next();
	            rec.otherValues.setField(fld);	// clone not required
	         }
    	 }
         
    	 if (Log.getDebugLevel() > 9)
         Log.log( 10, "(PwsRecord) record cloned : " + rec.toString() );
         return rec;  

      } catch ( CloneNotSupportedException e ) {
         return null;
      }
   }

   /**
    * Returns an exact copy of this record, but bearing a new UUID.  
    * 
    * @return <code>PwsRecord</code>
    */
   public PwsRecord copy () {
      PwsRecord r = (PwsRecord)clone();
      r.setRecordID( new UUID() );
      return r;
   }
   
   /**
    * Sets all record fields to zero values, except for Record-ID and CREATETIME.
    */
   public void clear () {
      setTitle( null );
      setEmail( (PwsPassphrase)null );
      setUsername( (PwsPassphrase)null );
      setGroup( null );
      setNotes( (PwsPassphrase)null );
      setPassword( null );
      try { setPassPolicy( null ); }
      catch ( InvalidPassphrasePolicy e ) {}
      setAutotype( null );
      setHistory( (PwsPassphrase)null );
      setUrl( (PwsPassphrase)null );
      setPassPolicyName(null);
      setKeyboardShortcut(null);
      setProtectedEntry(false);
      otherValues = null;
      
      passLifeTime = 0;
      passModTime = 0;
      accessTime = 0;
      expiryInterval = 0;

      runCommand = null;
      dclickAction = null;
      shiftDclickAction = null;
      keyboardShortcut = null;
      
      modified();
   }

   /**
    * Sets the modified time of this record to the current time.
    */
   protected void modified () {
      if ( !initializing ) {
         modifyTime = normalisedTime(System.currentTimeMillis());
      }
   }
   
/** Whether this record is valid, i.e. qualifies for storage in a file.
 * 
 * @return boolean <b>true</b> if and only if this record has a valid ID, 
 *         a password and a title
 */    
   public boolean isValid () {
      return getRecordID() != null &&
             getPassword() != null &&
             getTitle() != null;
   }
   
   /** Whether this record is identical to the parameter record. Added to the
    * "equals" criterion this extends to complete content equality.
    * 
    * @param rec <code>PwsRecord</code> to investigate (may be <b>null</b>)
    * @return boolean <b>true</b> if and only if the parameter is not 
    *         <b>null</b> and this record and the parameter record have 
    *         identical data signatures (<code>getSignature()</code>; includes 
    *         identity of record-ID)
    */    
   public boolean isIdentical ( PwsRecord rec ) {
      return rec != null && Util.equalArrays( rec.getSignature(), this.getSignature() );
   }

   /** Returns a textual error hint in case this record is invalid.
    *  Returns empty string otherwise.
    *  
    *  @return String
    */
   public String getInvalidText () {
      if ( getRecordID() == null )
         return "UUID missing";
      if ( getTitle() == null )
         return "title missing";
      if ( getPassword() == null )
         return "password missing";
      return "";
   }
   
   /** Whether this record's expire time is exceeded. 
    * 
    *  @return <b>true</b> if and only if there is a PASSLIFETIME defined and
    *          the current time is equal/higher than the PASSLIFETIME
    */ 
   public boolean hasExpired () {
      return willExpire( System.currentTimeMillis() );  
   }
   
   /** Whether this record's life time will expire until the date
    *  given. Returns <b>false</b> if parameter is zero. 
    * 
    *  @param date long compare time
    *  @return boolean <b>true</b> if and only if there is a PASSLIFETIME 
    *          defined and the compare time is higher than the PASSLIFETIME
    */ 
   public boolean willExpire ( long date )  {
      long t = getPassLifeTime();
      return t > 0 && date > t;  
   }

   /** Whether this record contains an EXTRA FIELD of the given type.
    * Stating canonical fields results in <b>false</b>.
    * 
    * @param type int field type
    * @return boolean
    */
   public boolean hasExtraField (int type) {
	   return otherValues == null ? false : otherValues.contains(type);
   }
   
   /** Returns the value of record field ACCESSTIME in epoch time. 
    *
    * @return long date in milliseconds
    */
   public long getAccessTime ()
   {
      return accessTime;
   }
   
   /** Sets the value of record field ACCESSTIME.
    * 
    * @param value long date value in milliseconds
    */
   public void setAccessTime ( long value )
   {
      value = value / 1000 * 1000;
      accessTime = value;
      if ( Log.getDebugLevel() > 4 )
      Log.debug( 5, "(PwsRecord) set ACCESSTIME value = " + value 
            + ", " + this );
   }
   
   /** Returns the value of record field CREATETIME in epoch milliseconds.
    * 
    * @return long date value in milliseconds
    */
   public long getCreateTime ()
   {
      return createTime;
   }
   
   /** Returns the value of record field MODIFYTIME in epoch milliseconds.
    * The precision is in seconds.
    * 
    *  @return long date value in milliseconds
    */
   public long getModifiedTime ()
   {
      return modifyTime;
   }

   /** Sets the value of record field CREATETIME.
    * 
    *  @param time long time value in epoch milliseconds
    */
   public void setCreateTime ( long time )
   {
      time = normalisedTime(time);
      controlValue( createTime, time, "CREATETIME" );
      createTime = time;
   }
   
   /** Sets the value of record field MODIFYTIME.
    * 
    *  @param time long time value in epoch milliseconds
    */
   public void setModifyTime ( long time )
   {
      time = normalisedTime(time);
      controlValue( modifyTime, time, "MODIFYTIME" );
      modifyTime = time;
   }
   
   /** Returns the value of record field PASSLIFETIME in epoch milliseconds.
    * 
    *  @return long date value in milliseconds
    */
   public long getPassLifeTime ()
   {
      return passLifeTime;
   }
   
   /** Sets the value of record field PASSLIFETIME.
    * 
    * @param value long time value in epoch milliseconds
    */
   public void setPassLifeTime ( long value )
   {
      value = value / 1000 * 1000;
      controlValue( passLifeTime, value, "PASSLIFETIME" );
      passLifeTime = value;
   }
   
   /** Sets the value of record field EXPIRY_INTERVAL.
    * 
    * @param value int time value in days of the period (0..3650)
    */
   public void setExpiryInterval ( int value )
   {
      value = Math.max( Math.min( value, 3650 ), 0 );
      controlValue( expiryInterval, value, "EXPIRY_INTERVAL" );
      expiryInterval = value;
   }
   
   /** Returns the value of record field EXPIRY_INTERVAL (days of period).
    * 
    *  @return int days of expire period
    */
   public int getExpiryInterval ()
   {
      return expiryInterval;
   }
   
   /** Returns the value of record field PASSMODTIME in epoch milliseconds.
    * 
    *  @return long date value in milliseconds
    */
   public long getPassModTime ()
   {
      return passModTime;
   }
   
   /** Sets the value of record field PASSMODTIME.
    * 
    * @param value long time value in epoch milliseconds
    */
   public void setPassModTime ( long value )
   {
      value = value / 1000 * 1000;
      controlValue( passLifeTime, value, "PASSMODTIME" );
      passModTime = value;
   }
   
   /** Returns the value of the password policy field of this record
    *  or <b>null</b> if this value is undefined. 
    *
    *  @return <code>PwsPassphrasePolicy</code> or null
    */
   public PwsPassphrasePolicy getPassPolicy ()
   {
      return passPolicy == null ? null : (PwsPassphrasePolicy)passPolicy.clone();
   }
   
   /** Sets the password policy reserved for this record. 
    *  Use <b>null</b> to clear the field.
    * 
    *  @param value <code>PwsPassphrasePolicy</code> valid policy or <b>null</b>
    *  @throws InvalidPassphrasePolicy if the parameter policy is not valid
    * */
   public void setPassPolicy ( PwsPassphrasePolicy value )
         throws InvalidPassphrasePolicy
   {
      if ( value != null && !value.isValid() )
         throw new InvalidPassphrasePolicy();
         
      controlValue( passPolicy, value, "PASSPOLICY" );
      passPolicy = value == null ? null : (PwsPassphrasePolicy)value.clone();
   }

   /** Returns the GROUP field of this record as a String or <b>null</b> if 
    * this value is undefined.
    * 
    * @return String or null
    */
   public String getGroup ()
   {
      return group;
   }

   /**
    * Returns a normalised GROUP name. Returns <b>null</b> if the parameter
    * was <b>null</b>.
    * <p><small>This method corrects errors in the '.' separator settings
    * within the value by removing misplaced occurences. The result can be 
    * smaller but not larger than the parameter value.</small>
    *  
    * @param group String GROUP name or <b>null</b>
    * @return normalised GROUP name or <b>null</b>
    */
   public static String groupNormalized ( String group )
   {
      if ( group != null ) {
         group = Util.substituteText( group, "..", "." );
         boolean ok = false;
         while ( !(group.isEmpty() | ok) ) {
            ok = true;
            group = group.trim();
            if ( group.startsWith( "." ) ) {
               group = group.substring( 1 );
               ok = false;
            }
            if ( group.endsWith( "." ) ) {
               group = group.substring( 0, group.length()-1 );
               ok = false;
            }
         }
      }
      return group;
   }
   
   /** Sets the GROUP field of this record to the parameter string value.
    *  The stored value is normalised by corrections as necessary
    *  (see class description).
    *  An empty string is treated equivalent to <b>null</b>. 
    *  
    *  @param group String or <b>null</b> to clear
    */
   public void setGroup ( String group )
   {
      // special normalisation of GROUP value (no double or leading or trailing '.') 
      group = groupNormalized( group );
      
      String old = this.group;
      this.group = normalisedStringParam( group );
      controlValue( old, this.group, "GROUP" );
   }

   /** Checks whether two objects (values for element type <code>name</code>) 
    * are equal. If they are not equal, the record's modified marker is set and 
    * a trace log is written for the new value.
    * 
    * @param old Object old field value
    * @param value Object new field value
    * @param name String field type name
    */
   protected void controlValue ( Object old, Object value, String name )
   {
      if ( !equalVal( old, value ) ) {
         modified();
         if ( Log.getDebugLevel() > 4 )
         Log.debug( 5, "(PwsRecord) set " + name + " value = \"" + value 
               + "\", " + this );
      }
   }
   
   /** Checks whether two long integer values for element <code>name</code>) 
    * are equal. If they are not equal, the record's modified marker is set and
    * a trace log is written for the new value.
    * 
    * @param old long old field value
    * @param value long new field value
    * @param name String field type name
    */
   protected void controlValue ( long old, long value, String name )
   {
      if ( old != value ) {
         modified();
         if ( Log.getDebugLevel() > 4 )
         Log.debug( 5, "(PwsRecord) set " + name + " value = " + value 
               + ", " + this );
      }
   }
   
   /**
    * Detects equality of two objects, allowing for void assignments 
    * (<b>null</b>) to be compared. 
    * 
    * @param o1 Object
    * @param o2 Object
    * @return boolean true == parameters/objects are equal
    */
   protected static boolean equalVal ( Object o1, Object o2 )
   {
      return (o1 == null && o2 == null ) ||
             (o1 != null && o2 != null && o1.equals( o2 )); 
   }
   
   /** Returns the value of the NOTES field of this record as a String
    *  or <b>null</b> if the field is undefined.
    *  
    *  @return String field value or null
    */
   public String getNotes ()
   {
      return notes == null ? null : notes.getString();
   }

   /** Returns the value of the NOTES field of this record as a 
    * <code>PwsPassphrase</code> or <b>null</b> if this field is undefined.
    * 
    * @return <code>PwsPassphrase</code> or <b>null</b>
    */
   public PwsPassphrase getNotesPws ()
   {
      return notes == null ? null : (PwsPassphrase)notes.clone();
   }

   /** Sets the NOTES field of this record to the parameter String value.
    *  An empty string will render as <b>null</b>. 
    *  Use <b>null</b> to clear the field.
    *  
    *  @param value String, may be null
    */
   public void setNotes ( String value )
   {
      value = normalisedStringParam( value );
      setNotes( value == null ? null : new PwsPassphrase( value ) );
   }

   /** Sets the NOTES field of this record to the value represented by the
    *  parameter <code>PwsPassphrase</code>. This allows the direct assignment
    *  of an encrypted value. A passphrase of length zero is equivalent to 
    *  <b>null</b>. Use <b>null</b> to clear the field.
    *  
    *  @param value <code>PwsPassphrase</code> or <b>null</b>
    */
   public void setNotes ( PwsPassphrase value )
   {
      if ( isVoidPassphrase( value ) ) {
         value = null;
      }
      controlValue( notes, value, "NOTES" );
      notes = value == null ? null : (PwsPassphrase)value.clone();
   }

   /** Whether the given passphrase is either null or of length zero.
    * 
    * @param pass <code>PwsPassphrase</code> or <b>null</b>
    * @return boolean true == parameter is void
    */
   protected static boolean isVoidPassphrase ( PwsPassphrase pass )
   {
      return pass == null || pass.isEmpty();
   }
   
   /** Returns the actual PASSWORD field value of this record as a protected
    *  <code>PwsPassphrase</code> object. Returns <b>null</b> if the password
    *  is undefined.
    *  
    *  @return <code>PwsPassphrase</code> or <b>null</b>
    */
   public PwsPassphrase getPassword ()
   {
      return password == null ? null : (PwsPassphrase)password.clone();
   }

   /** Sets the PASSWORD field of this record to the parameter value.
    *  A passphrase of length zero is equivalent to <b>null</b>. Use <b>null</b>
    *  to clear the field.
    *  <p>There are no semantic controls on the password value. 
    * 
    * @param value <code>PwsPassphrase</code> or <b>null</b>
    */
   public void setPassword ( PwsPassphrase value )
   {
      if ( isVoidPassphrase( value ) ) {
         value = null;
      }
      controlValue( password, value, "PASSWORD" );
      password = value == null ? null : (PwsPassphrase)value.clone();
   }

   /** Returns the TITLE field of this record as a String.
    *  Returns <b>null</b> if the field is undefined.
    *  
    *  @return String or <b>null</b>
    */
   public String getTitle ()
   {
      return title;
   }

   /** Sets the TITLE field of this record to the parameter String value.
    *  An empty string is equivalent to <b>null</b>. 
    *  Use <b>null</b> to clear the field.
    *  
    *  @param title String, may be null
    */
   public void setTitle ( String title )
   {
      String old = this.title;
      this.title = normalisedStringParam( title );
      controlValue( old, this.title, "TITLE" );
   }

   /** Returns the EMAIL field of this record as a <code>PwsPassphrase</code>
    *  or <b>null</b> if this field is undefined.
    *  
    *  @return <code>PwsPassphrase</code> or <b>null</b>
    */
   public PwsPassphrase getEmailPws ()
   {
      return email == null ? null : (PwsPassphrase)email.clone();
   }

   /** Returns the EMAIL field of this record as a <code>String</code>
    *  or <b>null</b> if this field is undefined.
    *  
    *  @return String or <b>null</b>
    */
   public String getEmail ()
   {
      return email == null ? null : email.getString();
   }

   /** Sets the EMAIL field of this record to the parameter String value.
    *  An empty string is equivalent to <b>null</b>. 
    *  Use <b>null</b> to clear the field.
    *  
    *  @param value String or <b>null</b>
    */
   public void setEmail ( String value )
   {
      value = normalisedStringParam( value );
      setEmail( value == null ? null : new PwsPassphrase( value ) );
   }

   /** Sets the value of the EMAIL field of this record to the value 
    *  represented by the parameter <code>PwsPassphrase</code>.
    *  A passphrase of length zero is equivalent to <b>null</b>.
    *  Use <b>null</b> to clear the field.
    * 
    * @param value <code>PwsPassphrase</code> or <b>null</b>
    */
   public void setEmail ( PwsPassphrase value )
   {
      if ( isVoidPassphrase( value ) ) {
         value = null;
      }
      controlValue( email, value, "EMAIL" );
      email = value == null ? null : (PwsPassphrase)value.clone();
   }

   /** Returns the value of the USERNAME field of this record as a String
    *  or <b>null</b> if this field is undefined.
    *  
    *  @return String or <b>null</b>
    */
   public String getUsername ()
   {
      return username == null ? null : username.getString();
   }

   /** Returns the value of the USERNAME field of this record as a 
    * <code>PwsPassphrase</code> or <b>null</b> if this field is undefined.
    *  
    *  @return <code>PwsPassphrase</code> or <b>null</b>
    */
   public PwsPassphrase getUsernamePws ()
   {
      return username == null ? null : (PwsPassphrase)username.clone();
   }

   /** Sets the value of the USERNAME field of this record to the parameter 
    *  <code>String</code> value. An empty string is equivalent to 
    *  <b>null</b>. Use <b>null</b> to clear the field.
    *  
    *  @param value String or <b>null</b>
    */
   public void setUsername ( String value )
   {
      value = normalisedStringParam( value );
      setUsername( value == null ? null : new PwsPassphrase(value) );
   }

   /** Sets the value of the USERNAME field of this record to the value 
    *  represented by the parameter <code>PwsPassphrase</code>.
    *  A passphrase of length zero is equivalent to <b>null</b>.
    *  Use <b>null</b> to clear the field.
    * 
    * @param value <code>PwsPassphrase</code> or <b>null</b>
    */
   public void setUsername ( PwsPassphrase value )
   {
      if ( isVoidPassphrase( value ) ) {
         value = null;
      }
      controlValue( username, value, "USERNAME" );
      username = value == null ? null : (PwsPassphrase)value.clone();
   }

   /** This sets PASSMODTIME and ACCESSTIME to the current system time and 
    * should be called after a password value was modified. 
    *  <p>For reasons of flexibility this is not automatically called when 
    *  modifying a password through <code>setPassword()</code>. Time values
    *  can be set independent from existence of the PASSWORD value.
    */ 
   public void passwordUpdated ()
   {
      long time = System.currentTimeMillis();
      setPassModTime( time );
      setAccessTime( time );
   }
   
   /** Adds an unknown data field to this record for the purpose of conservation.
    *  In contrast to <code>setExtraField()</code> no validation is performed on
    *  the type value. Does nothing if <code>data</code> is <b>null</b>.
    *  <p>Note: this value is stored encrypted internally during program session.
    *  A copy of the given data is used.
    * 
    * @param type int, field type number (0..255)
    * @param data byte array, field value (exact length)
    */
   protected void addUnknownField ( int type, byte[] data ) {
      if ( data == null ) return;
      
      if ( otherValues == null ) {
         otherValues = new RawFieldList();
      }
      PwsRawField raw = new PwsRawField( type, data );
      raw.setEncrypted(true);
      otherValues.setField( raw );
   }
   
   /** Adds an unknown field value to this record for the purpose of conservation.
    *  No validation is performed on the type value. Does nothing if 
    *  argument is <b>null</b>.
    *  <p>WARNING: The given field is stored in direct reference and modified 
    *  into 'encrypted' state.
    * 
    * @param field PwsRawField, may be <b>null</b>
    */
   protected void addUnknownField ( PwsRawField field) {
      if ( field == null ) return;
      
      if ( otherValues == null ) {
         otherValues = new RawFieldList();
      }
      field.setEncrypted(true);
      otherValues.setField( field );
   }
   
   /** Puts a data field into this record which forms a non-canonical field 
    * identified by its integer type code. Only non-canonical field types
    * may be entered; use the <b>null</b> value to clear the field from the list
    * of unknown fields.
    * <small>Notes: This value is stored internally in cleartext during 
    * program session. This method replaces a previous occurrence of same type
    * in the unknown field list. Whether a field value is canonical can be 
    * tested by <code>PwsFileFactory.isCanonicalField()</code>.</small>
    * 
    * @param type int, non-canonical field type number within 0..255
    * @param value field value, or <b>null</b> to remove the field
    * @param format the referenced file format version or 0 for default
    */
   public void setExtraField ( int type, byte[] value, int format ) {
	   setExtraField(type, value, 0, value == null ? 0 : value.length, format);
   }
   
   /** Puts a data field into this record which forms a non-canonical field 
    * identified by its integer type code. Only non-canonical field types
    * may be entered; use the <b>null</b> value to clear the field from the list
    * of unknown fields.
    * <small>Notes: This value is stored internally in cleartext during 
    * program session. This method replaces a previous occurrence of same type
    * in the unknown field list. Whether a field value is canonical can be 
    * tested by <code>PwsFileFactory.isCanonicalField()</code>.</small>
    * 
    * @param type int, non-canonical field type number within 0..255
    * @param value field value, or <b>null</b> to remove the field
    * @param start int data offset in value
    * @param length data length
    * @param format the referenced file format version or 0 for default
    */
   public void setExtraField ( int type, byte[] value, int start, int length, int format ) {
      // control field type
      if ( PwsFileFactory.isCanonicalField( type, format ) )
         throw new IllegalArgumentException( "canonical field type" );

      // ensure list instance
      if ( otherValues == null ) {
         otherValues = new RawFieldList();
      }
      
      // erase field from list
      if ( value == null ) {
         if ( otherValues.removeField( type ) != null ) {
            modified();
         }

      // add / replace new value
      } else {
    	 PwsRawField newValue = new PwsRawField(type, value, start, length);
    	 newValue.setEncrypted(true);
     	 PwsRawField oldValue = otherValues.setField( newValue );
     	 controlValue(oldValue, newValue, "EXTRAFIELD " + type);
      }
   }  // setExtraField
   
   /** Returns an iterator over all unknown fields stored for this record.
    *  
    * @return <code>Iterator</code> of element type <code>PwsRawField</code>
    */
   public Iterator<PwsRawField> getUnknownFields () {
	  if ( otherValues == null || otherValues.size() == 0 ) {
		  return emptyFieldIterator;
	  }
      return otherValues.iterator();
   }
   
   /**
    * Returns the number of data fields which are not canonical in this record.
    * (This includes fields added by <code>setExtraField()</code> method.)
    * 
    * @return int size of unknown field list
    */
   public int getUnknownFieldCount () {
      return otherValues == null ? 0 : otherValues.size();
   }
   
   /**
    * Returns the size of the data block required to store the content of
    * this record on a persistent state. (This takes into account the general 
    * file formating rules of a PWS file.) 
    * 
    * @param format int, the file format version of the persistent state
    * @param charset String, name of charset used to encode text
    * @return int required (blocked) data space
    * @throws IllegalCharsetNameException if charset is unknown to the executing
    *         VM
    */
   public long getBlockedDataSize ( int format, String charset )
   {
      long sum = 0;
      
      // constant size consisting of fields:
      switch ( format )  {
      
      case Global.FILEVERSION_3:
         sum = fieldBlockSizeUpdate( sum, url, format, charset );
         sum = fieldBlockSizeUpdate( sum, autotype, format, charset );
         sum = fieldBlockSizeUpdate( sum, history, format, charset );
         sum = fieldBlockSizeUpdate( sum, email, format, charset );
         sum = fieldBlockSizeUpdate( sum, passPolicyName, format, charset );
         sum = fieldBlockSizeUpdate( sum, keyboardShortcut, format, charset );
         sum = fieldBlockSizeUpdate( sum, runCommand, format, charset );
         sum = fieldBlockSizeUpdate( sum, dclickAction, format, charset );
         sum = fieldBlockSizeUpdate( sum, shiftDclickAction, format, charset );
         
         if ( passPolicy != null ) {
            sum = fieldBlockSizeUpdate( sum, passPolicy.getModernForm(), format,
            	  charset );
            if ( passPolicy.hasOwnSymbols() ) {
               sum = fieldBlockSizeUpdate( sum, new String( 
            		   passPolicy.getOwnSymbols() ), format, charset );
            }
         }
      
         if ( expiryInterval != 0 ) 
        	 sum += PwsRawField.pwsFieldBlockSize( 4, format );
         if ( protectedEntry ) 
        	 sum += PwsRawField.pwsFieldBlockSize( 1, format );
         
         
//      case Global.FILEVERSION_2:
         sum = fieldBlockSizeUpdate( sum, group, format, charset );
         sum += PwsRawField.pwsFieldBlockSize( 16, format );  // UUID
         
//         if ( format <= Global.FILEVERSION_2 && passPolicy != null )
//            sum += PwsRawField.pwsFieldBlockSize( 4, format );  // PassPolicy old format
         if ( accessTime != 0 )
            sum += PwsRawField.pwsFieldBlockSize( 8, format );  // access-Time
         if ( createTime != 0 )
            sum += PwsRawField.pwsFieldBlockSize( 8, format );  // create-Time
         if ( modifyTime != 0 )
            sum += PwsRawField.pwsFieldBlockSize( 8, format );  // modify-Time
         if ( passLifeTime != 0 )
            sum += PwsRawField.pwsFieldBlockSize( 8, format );  // password-life-Time
         if ( passModTime != 0 )
            sum += PwsRawField.pwsFieldBlockSize( 8, format );  // password-modify-Time
         
      
//      case Global.FILEVERSION_1:
         sum = fieldBlockSizeUpdate( sum, title, format, charset );
         sum = fieldBlockSizeUpdate( sum, username, format, charset );
         sum = fieldBlockSizeUpdate( sum, notes, format, charset );
         sum = fieldBlockSizeUpdate( sum, password, format, charset );
      }
      
      // size of extra fields (unknown fields) if present
      if ( otherValues != null ) {
         sum += otherValues.dataSize( format );
      }
      
      // add space for EOR marker (format V3) 
      sum += 16;
      return sum;
   }
   
   /**
    * Helper to calculate <code>getBlockedDataSize()</code>; adds the
    * store size of a text field, which may be a <code>String</code> or 
    * a <code>PwsPassphrase</code>. 
    * 
    * @param sum long, sum so far
    * @param field <code>String</code> or <code>PwsPassphrase</code>, 
    *        may be null
    * @param format int, format version of the persistent state
    * @param charset String, charset name used for encoding text 
    * 
    * @return sum + size of store data block of the parameter record field
    * @throws IllegalCharsetNameException if charset is unknown to the executing
    *         VM
    */
   private static long fieldBlockSizeUpdate ( long sum, Object field, 
		                                      int format, String charset )
   {
      byte[] data ;
      
      if ( field != null ) {
         if ( field instanceof String ) {
            try { 
            	data = ((String)field).getBytes( charset );
            } catch ( UnsupportedEncodingException e ) { 
               throw new IllegalCharsetNameException( charset ); 
            }
         } else if ( field instanceof PwsPassphrase ) {
            data = ((PwsPassphrase)field).getBytes( charset );
         } else if ( field instanceof PwsRawField ) {
            data = ((PwsRawField)field).getData();
         } else if ( field instanceof KeyStroke ) {
             data = new byte[4];
         } else { 
        	throw new IllegalStateException( "illegal FIELD parameter type" );
         }

         sum += PwsRawField.pwsFieldBlockSize( data.length, format );
         Util.destroy( data );

      // for null fields
      } else if ( format < Global.FILEVERSION_3 ) {
         sum += 16;
      }
      return sum;
   }
   
   
   /**
    * Returns the total data size of all unknown fields in this record.
    * (This refers to blocked data size according to the specified file format.)
    * 
    * @param format int, the format version of the persistent state to be 
    *        considered
    * @return long, data size of "unknown" fields
    */
   public long getUnknownFieldSize ( int format ) {
      return otherValues == null ? 0 : otherValues.dataSize( format );
   }
   
   /**
    * Permanently removes all unknown (or "extra") fields from this record. 
    */
   public void clearExtraFields () {
      if ( otherValues != null ) {
         otherValues.clear();
      }
   }
   
   /** Returns a copy of a field value from the "unknown" field list of this 
    * record that matches the given field type code.
    *  
    * @param type int, field type number (0..255)
    * @return byte[], cleartext field value or <b>null</b> if field is not 
    *         available
    */
   public byte[] getExtraField ( int type ) {
      PwsRawField fld;
      
      if ( otherValues != null && (fld = otherValues.getField( type )) != null )
         return fld.getData();
      return null ; 
   }
   
   /** Returns a normalised version of the parameter String value.
    *  For a value not <b>null</b>: trims the value, and if the result equals
    *  the empty string, the value is transformed into a <b>null</b> value. 
    *  
    *  @return String normalised value or <b>null</b>
    */ 
   protected static String normalisedStringParam ( String param ) {
      if ( param != null ) {
         param = param.trim();
         if ( param.length() == 0 ) {
            param = null;
         }
      }
      return param;
   }
   
   /** Opportunity to set an initializing phase for a record. If true,
    *  any field setup will not cause the record modify time (MODIFYTIME) to 
    *  get updated.
    * 
    *  @param b boolean, <b>true</b> == init phase active
    */ 
   public void setInitialize ( boolean b )
   {
      initializing = b;
   }
   
   /** Returns the RECORD-ID field of this record as a <code>UUID</code> object.
    * 
    * @return <code>UUID</code>
    */
   public UUID getRecordID ()
   {
      return recordID;
   }

   /** Sets the RECORD-ID field of this record from the parameter <code>UUID
    *  </code> value. Should be used with great care! (This does not update any
    *  time fields.)
    *  
    * @param uuid <code>UUID</code>, the new Record-ID value
    * @throws NullPointerException if parameter is <b>null</b>
    */
   public void setRecordID ( UUID uuid )
   {
      if ( uuid == null )
         throw new NullPointerException();
      
      UUID old = recordID; 
      recordID = uuid;
      Log.log( 4, "(PwsRecord) set record-ID to: " + recordID + ", " + old );
   }
   
   /** Returns the import status. If this record was imported by the 
    *  <code>PwsRecordList.merge()</code> method, it will carry one 
    *  of the status flags IMPORTED or IMPORTED_CONFLICT.
    * 
    *  @return int, record's import status (0 for no flag)
    */ 
   public int getImportStatus ()
   {
      return importStatus;
   }
   
   /** Sets the import status of this record.
    * 
    * @param v int, the import status flag to be set
    */
   public void setImportStatus ( int v )
   {
      importStatus = v;
   }
   
/**
 * Whether this record equals the parameter object.
 * 
 * @param obj <code>Object</code>, compare object, may be <b>null</b>
 * @return <b>true</b> if and only if the parameter compare object is a
 * 			<code>PwsRecord</code> with RECORD-ID same as this record's ID 
 */
   @Override
   public boolean equals ( Object obj )
   {
	   if ( obj == null || !(obj instanceof PwsRecord)) return false;
       return recordID.equals( ((PwsRecord)obj).recordID );
   }

/** A hashcode value coherent with the <code>equals</code> function.
 * 
 * @return int
 */   
   @Override
   public int hashCode ()
   {
      return recordID.hashCode();
   }

   /**
    * A String representation of this record. Renders the Record-ID.
    * <br>Example/format: "{01234567-89ab-cdef-0123-456789abcdef}" 
    * 
    * @return String
    */
   @Override
   public String toString ()
   {
      return recordID.toString();
   }
   
   /**
    * Returns a CRC checksum value for the contents of this record. The sum 
    * includes the record-ID value.
    * <p><small>It may not be assumed that this value is identical over 
    * different releases of this software package. It may be assumed that it is
    * identical over different program sessions with the same software package.
    * </small>
    * 
    * @return int, CRC32 value incorporating all variable record elements 
    */
   public int getCRC ()
   {
      CRC32 crc = new CRC32();
   
      ByteArrayOutputStream output = new ByteArrayOutputStream();
      DataOutputStream out = new DataOutputStream( output );
      
      try {
         out.write( recordID.getBytes() );
   
         if ( password != null ) {
            // secure integration of a password value crc
            out.writeInt( password.hashCode() );
         }
         if ( passPolicy != null ) {
            out.writeInt( passPolicy.getIntForm() );
            out.writeChars( new String( passPolicy.getActiveSymbols() ));
         }
   
         out.writeLong( accessTime );
         out.writeLong( createTime );
         out.writeLong( modifyTime );
         out.writeLong( passLifeTime );
         out.writeLong( passModTime );
         out.writeInt( expiryInterval );
         out.writeInt( importStatus );
         out.writeBoolean( protectedEntry );

         if ( title != null )
            out.writeChars( title );
         if ( email != null )
            out.writeInt( email.hashCode() );
         if ( group != null )
            out.writeChars( group );
         if ( username != null )
            out.writeInt( username.hashCode() );
         if ( notes != null )
            out.writeInt( notes.hashCode() );
         if ( history != null )
            out.writeInt( history.hashCode() );
         if ( url != null )
            out.writeInt( url.hashCode() );
         if ( autotype != null )
            out.writeChars( autotype );
         if ( passPolicyName != null )
             out.writeChars( passPolicyName );
         if ( keyboardShortcut != null )
             out.writeInt( keyboardShortcut.hashCode() );

         // unknown fields
         for ( Iterator<PwsRawField> it = getUnknownFields(); it.hasNext(); ) {
        	PwsRawField ufld = it.next();
            out.write( ufld.type );
            out.write( ufld.getCrc() );
         }
         out.close();
         
      } catch ( IOException e ) {
         System.out.println( "*** ERROR in PwsRecord CRC : " + e );
         return -1;
      }
      
      crc.update( output.toByteArray() );
      return (int)crc.getValue();
   }  // getCRC

   /**
    * Renders a unique signature value of this record and its actual data state.
    * Returns a SHA-256 checksum over all data content of this record, including
    * its UUID value. (Each record is guaranteed an individual value, 
    * regardless of its data content.)  
    * <p>There is no guarantee that this value is identical over different 
    * releases of this software, however, it may be assumed that it is
    * identical over different program sessions running the same package.
    * 
    * @return byte[] 32 byte signature value (SHA-256 digest) 
    */
   public byte[] getSignature ()
   {
      ByteArrayOutputStream output = new ByteArrayOutputStream();
      DataOutputStream out = new DataOutputStream( output );
      SHA256 sha = new SHA256();
      
      try {
         out.write( recordID.getBytes() );

         if ( password != null )
            // secure integration of a password value crc
            out.writeInt( password.hashCode() );

         if ( passPolicy != null ) {
            out.writeInt( passPolicy.getIntForm() );
            out.writeChars( new String( passPolicy.getActiveSymbols() ));
         }

         out.writeLong( accessTime );
         out.writeLong( createTime );
         out.writeLong( modifyTime );
         out.writeLong( passLifeTime );
         out.writeLong( passModTime );
         out.writeInt( expiryInterval );
         out.writeBoolean( protectedEntry );

         if ( title != null )
            out.writeChars( title );
         if ( email != null )
            out.writeInt( email.hashCode() );
         if ( group != null )
            out.writeChars( group );
         if ( username != null )
            out.writeInt( username.hashCode() );
         if ( notes != null )
            out.writeInt( notes.hashCode() );
         if ( history != null )
             out.writeInt( history.hashCode() );
         if ( url != null )
             out.writeInt( url.hashCode() );
         if ( autotype != null )
             out.writeChars( autotype );
         if ( passPolicyName != null )
             out.writeChars( passPolicyName );
         if ( keyboardShortcut != null )
             out.writeChars( keyboardShortcut.toString() );
         
         
         // unknown fields
         for ( Iterator<PwsRawField> it = getUnknownFields(); it.hasNext(); ) {
        	PwsRawField ufld = it.next();
            out.write( ufld.type );
            out.write( ufld.getCrc() );
         }
         out.close();

      } catch ( IOException e ) {
         System.out.println( "*** ERROR in creating PwsRecord Signature : " + e );
         return null;
      }
      
      sha.update( output.toByteArray() );
      return sha.digest();
   }  // getSignature


/**
 * Returns the AUTOTYPE text string of this record or <b>null</b> if undefined.
 * 
 * @return String value or <b>null</b>
 */
public String getAutotype ()
{
   return autotype;
}

/**
 * Set the AUTOTYPE text field of this record to the parameter value.
 * Use <b>null</b> or empty string to clear the field.
 * 
 * @param value String 
 */
public void setAutotype ( String value )
{
   String old = autotype;
   autotype = normalisedStringParam( value );
   controlValue( old, autotype, "AUTOTYPE" );
}

/**
 *  Content of the password HISTORY textfield as a passphrase.
 *  Returns <b>null</b> if this field is undefined.
 *  
 *  @return <code>PwsPassphrase</code> or <b>null</b>
 */
public PwsPassphrase getHistoryPws ()
{
   return history == null ? null : (PwsPassphrase)history.clone();
}

/**
 *  Content of the password HISTORY text field as a string or
 *  <b>null</b> if this field is undefined.
 *  <p>(See PWS format document for details of the content.) 
 * 
 * @return String history value or <b>null</b>
 */
public String getHistory ()
{
   return history == null ? null : history.getString();
}

/** Sets the value of the HISTORY field of this record to the parameter 
 *  <code>String</code> value. An empty string is equivalent to 
 *  <b>null</b>. Use <b>null</b> to clear the field.
 *  <p>(See PWS format document for details of the content.) 
 *  
 *  @param value String history value or null
 */
public void setHistory ( String value )
{
   value = normalisedStringParam( value );
   setHistory( value == null ? null : new PwsPassphrase( value ) );
}

/**
 * Sets the value of the HISTORY field  of this record to the value 
 *  represented by the parameter <code>PwsPassphrase</code>.
 *  A passphrase of length zero is equivalent to <b>null</b>.
 *  Use <b>null</b> to clear the field.
 *  <p>(See PWS format document for details of the content.) 
 *  
 * @param value <code>PwsPassphrase</code> or null
 */
public void setHistory ( PwsPassphrase value )
{
   if ( isVoidPassphrase( value ) )
      value = null;
   controlValue( history, value, "HISTORY" );
   history = value == null ? null : (PwsPassphrase)value.clone();
}

/**
 *  Content of the URL text field as a passphrase.
 *  Returns <b>null</b> if the field is undefined.
 *  
 *  @return <code>PwsPassphrase</code> or <b>null</b>
*/
public PwsPassphrase getUrlPws ()
{
   return url == null ? null : (PwsPassphrase)url.clone();
}

/**
 *  Content of the URLFIELD text field as a text string or
 *  <b>null</b> if this field is undefined.
 * 
 * @return String or <b>null</b>
 */
public String getUrl ()
{
   return url == null ? null : url.getString();
}

/** Sets the value of the URLFIELD field of this record to the parameter 
 *  <code>String</code> value. An empty string will render equivalent to 
 *  <b>null</b>. Use <b>null</b> to clear the field.
 */
public void setUrl ( String value )
{
   value = normalisedStringParam( value );
   setUrl( value == null ? null : new PwsPassphrase( value ) );
}

/**
 * Sets the value of the URLFIELD field of this record to the value 
 *  represented by the parameter <code>PwsPassphrase</code>.
 *  A passphrase of length zero is equivalent to <b>null</b>.
 *  Use <b>null</b> to clear the field.
 *  
 * @param value <code>PwsPassphrase</code> or <b>null</b>
 */
public void setUrl ( PwsPassphrase value )
{
   if ( isVoidPassphrase( value ) ) {
      value = null;
   }
   controlValue( this.url, value, "URLFIELD" );
   this.url = value == null ? null : (PwsPassphrase)value.clone();
}

/**
 * Returns the string expression of the parent group to the
 * given group name or <b>null</b>. 
 * 
 * @param group String correct group name (including empty string)
 *        or <b>null</b>
 * @return String, group name or <b>null</b> if no parent exists
 */
public static String groupParent ( String group )
{
   if ( group != null && group.length() != 0 ) {
      int i = group.lastIndexOf('.');
      if ( i > 0 ) {
         return group.substring(0, i);
      }
   }
   return null;   
}

/** Whether this record bears a protection marker, like e.g.
 * for a read-only interpretation.
 * 
 * @return boolean true == protected flag set
 */
public boolean getProtectedEntry ()
{
   return protectedEntry;
}

/** Set the "Protected Entry" marker for this record.
 * 
 * @param protectedEntry boolean <b>true</b> == protected
 */
public void setProtectedEntry ( boolean protectedEntry )
{
   boolean oldValue = this.protectedEntry;
   this.protectedEntry = protectedEntry;
   controlValue( new Boolean(oldValue), new Boolean(protectedEntry), "PROTECTED_ENTRY" );
}

/** If the password policy for this record is defined by a policy name
 * (rather than an individual policy) then the name is returned here,
 * <b>null</b> otherwise.
 * 
 * @return String Policy Name or <b>null</b> if undefined
 */
public String getPassPolicyName ()
{
   return passPolicyName;
}

/** Sets a Password Policy Name for this record. This attempts to define
 * the password policy via a template name, ranking over a directly supplied
 * policy. (The template is to be defined in a file header value! 
 * The name here, however, can be supplied without control.)
 *  
 * @param policyName String policy name or <b>null</b> to clear
 */
public void setPassPolicyName ( String policyName )
{
   if (policyName != null && policyName.isEmpty()) {
	   policyName = null;
   }
   String oldValue = this.passPolicyName;
   this.passPolicyName = policyName;
   controlValue( oldValue, policyName, "PASSPOLICY_NAME" );
}

/** Returns the keyboard shortcut value for this record as a 
 * <code>KeyStroke</code> or <b>null</b> if not defined. 
 * 
 * @return <code>KeyStroke</code> shortcut key or <b>null</b>
 */
public KeyStroke getKeyboardShortcut () 
{
	return keyboardShortcut == null ? null : keyboardShortcut;
}

/** Sets the keyboard shortcut value for this record. Use <b>null</b> to clear.
 * 
 * @param shortcut <code>KeyStroke</code> or <b>null</b>
 */
public void setKeyboardShortcut ( KeyStroke shortcut ) {
	KeyStroke oldValue = keyboardShortcut;
	keyboardShortcut = shortcut == null ? null : shortcut;
    controlValue( oldValue, keyboardShortcut, "KEYBOARD_SHORTCUT" );
}

}
