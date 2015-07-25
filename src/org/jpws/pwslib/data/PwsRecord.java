
/*
 *  PwsRecord in org.jpws.pwslib.data
 *  file: PwsRecord.java
 * 
 *  Project JPasswords
 *  @author Wolfgang Keller
 *  Created 11.08.2004
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

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.IllegalCharsetNameException;
import java.util.Iterator;
import java.util.zip.CRC32;

import org.jpws.pwslib.crypto.SHA256;
import org.jpws.pwslib.exception.InvalidPassphrasePolicy;
import org.jpws.pwslib.global.Global;
import org.jpws.pwslib.global.Log;
import org.jpws.pwslib.global.UUID;
import org.jpws.pwslib.global.Util;

/**
 * This class is a container for all data fields belonging to a <i>PasswordSafe</i>
 * record. Not all fields have to be assigned a value, and the Record-ID - a
 * {@link org.jpws.pwslib.global.UUID} object that holds an immutable universal 
 * ID value - is by design always existent on a <code>PwsRecord</code>.
 * A minimum set of non-empty fields must be assigned to a record
 * in order to become "valid" (e.g. a requisite to get saved on a persistent file).
 * These fields are: <b>TITLE</b> and <b>PASSWORD</b>.
 * 
 * <p>Valid instances of this class can be added to and updated at a 
 * {@link PwsRecordList} object. Any iterator over instances of 
 * <code>PwsRecord</code> may be directly used to create a <i>PasswordSafe</i> file
 * (persistent state) by using the <code>PwsFileFactory.save()</code> methods.
 * There is no guarantee, however, that instances obtained from a <code>PwsFile</code>
 * will be valid (files are allowed to load invalid records).  
 * 
 * <p><u>Transient Properties</u>
 * <p>The record property <b>"ImportStatus"</b> may be set by user or automatically
 * through <code>PwsRecordList.merge()</code>. It is purely informational, but it 
 * is not reflected to the persistent state of a <code>PwsFile</code>. 
 * 
 * <p><u>Non-Canonical Fields</u> (since 0-4-0)
 * <p>Field types outside of the canon defined for the PWS file formats are supported
 * in various ways. A) Non-canonical fields coming from other applications are tolerated
 * and stored back to a persistent state when this record is saved. B) An application may
 * utilize <b>Extra Fields</b> (one field value per type) by use of methods
 * <code>setExtraField()</code> and <code>getExtraField()</code>. These fields also
 * are part of the persistent state and the non-canonical field list. 
 * 
 * <p><u>Conventions:</u>
 * <p><b>Normalized Group Names</b>. Group names, as values of the record field GROUP, 
 * may contain any sequence of valid group names separated by a "." character. 
 * No "." character is permitted at the beginning or end of the value. No empty 
 * elementary name is permitted ("..").  The "." character always has the meaning 
 * of separating grouping levels and must not be used for elementary name expressions.
 * 
 * @see PwsFileFactory
 *
 */
public class PwsRecord implements Cloneable
{
   /** Import status indicating that this record was added by the <code>merge()</code>
    *  method of <code>PwsRecordList</code>.
    *  @since 0-3-0
    */
   public static final int IMPORTED = 1;
   
   /** Import status indicating that this record was added by the <code>merge()</code>
    *  method of <code>PwsRecordList</code> by overwriting an existing record.
    *  @since 0-3-0
    */
   public static final int IMPORTED_CONFLICT = 2;

   /** Stores field values whose identity is unknown to this library 
    * (non-canonical fields). This includes fields that may be imported
    * from other applications or fields set by the "setExtraField()" method.
    * @since 2-0-0 modified type
    */
   private RawFieldList     otherValues;
   
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
   private String           autotype;
   private String           passPolicyName;
   private int              expiryInterval;
   private boolean          protectedEntry;
   
   // unused V3.10 fields
   PwsRawField              runCommand;
   PwsRawField              dclickAction;
   PwsRawField              shiftDclickAction;
   
   // the following time values are stored in "epoch" milliseconds
   private long             createTime;
   private long             passLifeTime;
   private long             passModTime;
   private long             accessTime;
   private long             modifyTime;
   
   private int              importStatus;
   private boolean          initializing;

  
   
/**
 *  Creates a new PWS record with a new Record-ID (UUID). The ID is automatically
 *  generated.  
 */
public PwsRecord ()
{
   recordID = new UUID();
   createTime = System.currentTimeMillis();
   modifyTime = createTime;
   Log.log( 4, "(PwsRecord) new PwsRecord: " + this.toString() );
}

/**
 *  Creates a new PWS record with a new Record-ID (UUID) and the specified
 *  CREATETIME.   
 */
public PwsRecord ( long time )
{
   recordID = new UUID();
   createTime = time;
   modifyTime = time;
   Log.log( 4, "(PwsRecord) new PwsRecord: time == " + time +", " + this.toString() );
}

/**
 *  Creates a new PWS record with a Record-ID as specified by the parameter
 *  UUID.
 *  
 *  @throws NullPointerException if the parameter is <b>null</b>  
 */
public PwsRecord ( UUID recID )
{
   if ( recID == null )
      throw new NullPointerException();
   
   recordID = recID;
   createTime = System.currentTimeMillis();
   modifyTime = createTime;
   Log.log( 4, "(PwsRecord) new PwsRecord (param): " + this.toString() );
}

/** Makes a deep clone of this record. 
 */
   public Object clone () 
   {
      PwsRecord rec;
      Iterator it;
      PwsRawField fld;
      
      try { 
         rec = (PwsRecord)super.clone();

         rec.password = getPassword();
         rec.passPolicy = getPassPolicy();
         rec.username = getUsernamePws();
         rec.email = getEmailPws();
         rec.notes = getNotesPws();
         rec.url = getUrlPws();
         rec.history = getHistoryPws();
         
         // deep clone of unknown fields
         rec.otherValues = null;
         for ( it = getUnknownFields(); it != null && it.hasNext(); )
         {
            fld = (PwsRawField)it.next();
            rec.addUnknownField( fld.type, fld.getData() );
         }
         
         Log.log( 10, "(PwsRecord) record cloned : " + rec.toString() );
         return rec;  
         }
      catch ( CloneNotSupportedException e )
      {
         return null;
      }
   }

   /**
    * Returns an exact copy of this record, but bearing a new UUID.  
    * @return <code>PwsRecord</code>
    */
   public PwsRecord copy ()
   {
      PwsRecord r = (PwsRecord)clone();
      r.setRecordID( new UUID() );
      return r;
   }
   
   /**
    * Sets all record fields to zero values, except for Record-ID and CREATETIME.
    */
   public void clear ()
   {
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
      otherValues = null;
      
      passLifeTime = 0;
      passModTime = 0;
      accessTime = 0;

      modified();
   }

   /**
    * Sets the modified time of this record to the current time.
    */
   private void modified ()
   {
      if ( !initializing )
         modifyTime = System.currentTimeMillis();
   }
   
/** Whether this record is valid, i.e. qualifies for storage in a file.
 * 
 * @return <b>true</b> if and only if this record has a valid ID, a password and
 *         a title
 */    
   public boolean isValid ()
   {
      return getRecordID() != null &&
             getPassword() != null &&
             getTitle() != null;
   }
   
   /** Whether this record is identical to the parameter record. (Added to the
    * "equals" criterion this extends to complete content equality.)
    * 
    * @param rec PwsRecord to investigate (may be <b>null</b>)
    * @return <b>true</b> if and only if the parameter is not <b>null</b> and
    *         this record and the parameter record have identical data signatures 
    *         (<code>getSignature()</code>; includes identity of record-ID)
    * @since 0-6-0
    */    
   public boolean isIdentical ( PwsRecord rec )
   {
      return rec != null && Util.equalArrays( rec.getSignature(), this.getSignature() );
   }

   /** Returns a textual error hint in case this record is invalid.
    *  Returns empty string otherwise.
    *  @since 0-4-0
    */
   public String getInvalidText ()
   {
      if ( getRecordID() == null )
         return "UUID missing";
      if ( getTitle() == null )
         return "title missing";
      if ( getPassword() == null )
         return "password missing";
      return "";
   }
   
   /** Whether this record's expiry time is exceeded. 
    * 
    *  @return <b>true</b> if and only if there is a PASSLIFETIME defined and
    *          the current time is equal/higher than the PASSLIFETIME
    *  @since 0-3-0
    */ 
   public boolean hasExpired ()
   {
      return willExpire( System.currentTimeMillis() );  
   }
   
   /** Whether this record's life time will be exired until the date
    *  given. Returns <b>false</b> if parameter is zero. 
    * 
    *  @param date compare time
    *  @return <b>true</b> if and only if there is a PASSLIFETIME defined and
    *          the compare time is equal/higher than the PASSLIFETIME
    *  @since 0-3-0
    */ 
   public boolean willExpire ( long date )
   {
      long t;
      return (t=getPassLifeTime()) > 0 && date >= t;  
   }
   
   /** Returns the value of record field ACCESSTIME in epoch timemillis. */
   public long getAccessTime ()
   {
      return accessTime;
   }
   
   /** Sets the value of record field ACCESSTIME.
    * @param value  time value in epoch milliseconds
    */
   public void setAccessTime ( long value )
   {
      value = value / 1000 * 1000;
      accessTime = value;
      if ( Log.getDebugLevel() > 4 )
      Log.debug( 5, "(PwsRecord) set ACCESSTIME value = " + value 
            + ", " + this );
   }
   
   /** Returns the value of record field CREATETIME in epoch timemillis. */
   public long getCreateTime ()
   {
      return createTime;
   }
   
   /** Returns the value of record field MODIFYTIME in epoch timemillis. */
   public long getModifiedTime ()
   {
      return modifyTime;
   }

   /** Sets the value of record field CREATETIME.
    *  @param time  time value in epoch milliseconds
    */
   public void setCreateTime ( long time )
   {
      time = time / 1000 * 1000;
      controlValue( createTime, time, "CREATETIME" );
      createTime = time;
   }
   
   /** Sets the value of record field MODIFYTIME.
    *  @param time  time value in epoch milliseconds
    */
   public void setModifyTime ( long time )
   {
      time = time / 1000 * 1000;
      controlValue( modifyTime, time, "MODIFYTIME" );
      modifyTime = time;
   }
   
   /** Returns the value of record field PASSLIFETIME in epoch timemillis. */
   public long getPassLifeTime ()
   {
      return passLifeTime;
   }
   
   /** Sets the value of record field PASSLIFETIME.
    * @param value  time value in epoch milliseconds
    */
   public void setPassLifeTime ( long value )
   {
      value = value / 1000 * 1000;
      controlValue( passLifeTime, value, "PASSLIFETIME" );
      passLifeTime = value;
   }
   
   /** Sets the value of record field EXPIRY_INTERVAL.
    * @param value  time value in days of the period (0..3650)
    */
   public void setExpiryInterval ( int value )
   {
      value = Math.max( Math.min( value, 3650 ), 0 );
      controlValue( expiryInterval, value, "EXPIRY_INTERVAL" );
      expiryInterval = value;
   }
   
   /** Returns the value of record field EXPIRY_INTERVAL (days of period). */
   public int getExpiryInterval ()
   {
      return expiryInterval;
   }
   
   /** Returns the value of record field PASSMODTIME in epoch timemillis. */
   public long getPassModTime ()
   {
      return passModTime;
   }
   
   /** Sets the value of record field PASSMODTIME.
    * @param value  time value in epoch milliseconds
    */
   public void setPassModTime ( long value )
   {
      value = value / 1000 * 1000;
      controlValue( passLifeTime, value, "PASSMODTIME" );
      passModTime = value;
   }
   
   /** Returns the value of the password policy field of this record
    *  or <b>null</b> if this value is undefined. */
   public PwsPassphrasePolicy getPassPolicy ()
   {
      return passPolicy == null ? null : (PwsPassphrasePolicy)passPolicy.clone();
   }
   
   /** Sets the password policy reserved for this record. 
    *  Use <b>null</b> to clear the field.
    * 
    *  @param value a valid <code>PwsPassphrasePolicy</code> or <b>null</b>
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

   /** Returns the GROUP field of this record as a String.
    *  Returns <b>null</b> if the field is undefined.
    */
   public String getGroup ()
   {
      return group;
   }

   /**
    * Normalisation of a GROUP name.
    *  
    * @param group String GROUP name or <b>null</b>
    * @return normalised GROUP name or <b>null</b>
    * @since 0-6-0
    */
   public static String groupNormalized ( String group )
   {
      boolean ok;

      if ( group != null )
      {
         group = Util.substituteText( group, "..", "." );
         ok = false;
         while ( !(group.equals("") | ok) )
         {
            ok = true;
            group = group.trim();
            if ( group.startsWith( "." ) )
            {
               group = group.substring( 1 );
               ok = false;
            }
            if ( group.endsWith( "." ) )
            {
               group = group.substring( 0, group.length()-1 );
               ok = false;
            }
         }
      }
      return group;
   }
   
   /** Sets the GROUP field of this record to the parameter String value.
    *  The stored value receives normalization and correction as necessary
    *  (see class description).
    *  An empty string is treated equivalent to <b>null</b>. 
    *  Use <b>null</b> to clear the field.
    */
   public void setGroup ( String group )
   {
      String old;

      // special normailzation of GROUP value (no double or leading or trailing '.') 
      group = groupNormalized( group );
      
      old = this.group;
      this.group = transformedStringParam( group );
      controlValue( old, this.group, "GROUP" );
   }

   /** Checks whether two objects (values for element type <code>name</code>) are equal. 
    *  If they are not equal, the record's modified marker is set and a trace log 
    *  is written for the new value.
    */
   private void controlValue ( Object old, Object value, String name )
   {
      if ( !equalVal( old, value ) )
      {
         modified();
         if ( Log.getDebugLevel() > 4 )
         Log.debug( 5, "(PwsRecord) set " + name + " value = \"" + value 
               + "\", " + this );
      }
   }
   
   /** Checks whether two long integer values for element <code>name</code>) are equal. 
    *  If they are not equal, the record's modified marker is set and a trace log 
    *  is written for the new value.
    */
   private void controlValue ( long old, long value, String name )
   {
      if ( old != value )
      {
         modified();
         if ( Log.getDebugLevel() > 4 )
         Log.debug( 5, "(PwsRecord) set " + name + " value = " + value 
               + ", " + this );
      }
   }
   
   /**
    * Detects equality of two objects, allowing for void assignments (<b>null</b>). 
    */
   private boolean equalVal ( Object o1, Object o2 )
   {
      return (o1 == null & o2 == null ) ||
             (o1 != null && o2 != null && o1.equals( o2 )); 
   }
   
   /** Returns the value of the NOTES field of this record as a String.
    *  Returns <b>null</b> if the field is undefined.
    */
   public String getNotes ()
   {
      return notes == null ? null : notes.getString();
   }

   /** Returns the value of the NOTES field of this record as a <code>PwsPassphrase</code>.
    *  Returns <b>null</b> if the field is undefined.
    */
   public PwsPassphrase getNotesPws ()
   {
      return notes == null ? null : (PwsPassphrase)notes.clone();
   }

   /** Sets the NOTES field of this record to the parameter String value.
    *  An empty string will render equivalent to <b>null</b>. 
    *  Use <b>null</b> to clear the field.
    */
   public void setNotes ( String value )
   {
      value = transformedStringParam( value );
      setNotes( value == null ? null : new PwsPassphrase( value ) );
   }

   /** Sets the NOTES field of this record to the value represented by the
    *  parameter <code>PwsPassphrase</code>. This allows the direct incorporation
    *  of an encrypted value. A passphrase of length zero is equivalent to <b>null</b>.
    *  Use <b>null</b> to clear the field.
    */
   public void setNotes ( PwsPassphrase value )
   {
      if ( voidPassphrase( value ) )
         value = null;
      controlValue( notes, value, "NOTES" );
      notes = value == null ? null : (PwsPassphrase)value.clone();
   }

   private boolean voidPassphrase ( PwsPassphrase pass )
   {
      return pass == null || pass.isEmpty();
   }
   
   /** Returns the actual PASSWORD field value of this record as a protected
    *  <code>PwsPassphrase</code> object. Returns <b>null</b> if the password
    *  is undefined.
    */
   public PwsPassphrase getPassword ()
   {
      return password == null ? null : (PwsPassphrase)password.clone();
   }

   /** Sets the PASSWORD field of this record to the parameter value.
    *  There are not controls on the password value. A passphrase of length
    *  zero is equivalent to <b>null</b>.
    * 
    * @param value <code>PwsPassphrase</code>, the new password value;
    *        use <b>null</b> to clear the field.
    */
   public void setPassword ( PwsPassphrase value )
   {
      if ( voidPassphrase( value ) )
         value = null;
      controlValue( password, value, "PASSWORD" );
      password = value == null ? null : (PwsPassphrase)value.clone();
   }

   /** Returns the TITLE field of this record as a String.
    *  Returns <b>null</b> if the field is undefined.
    */
   public String getTitle ()
   {
      return title;
   }

   /** Sets the TITLE field of this record to the parameter String value.
    *  An empty string will render equivalent to <b>null</b>. 
    *  Use <b>null</b> to clear the field.
    */
   public void setTitle ( String title )
   {
      String old = this.title;
      this.title = transformedStringParam( title );
      controlValue( old, this.title, "TITLE" );
   }

   /** Returns the EMAIL field of this record as a <code>PwsPassphrase</code>.
    *  Returns <b>null</b> if the field is undefined.
    */
   public PwsPassphrase getEmailPws ()
   {
      return email == null ? null : (PwsPassphrase)email.clone();
   }

   /** Returns the EMAIL field of this record as a <code>String</code>.
    *  Returns <b>null</b> if the field is undefined.
    */
   public String getEmail ()
   {
      return email == null ? null : email.getString();
   }

   /** Sets the EMAIL field of this record to the parameter String value.
    *  An empty string will render equivalent to <b>null</b>. 
    *  Use <b>null</b> to clear the field.
    */
   public void setEmail ( String value )
   {
      value = transformedStringParam( value );
      setEmail( value == null ? null : new PwsPassphrase( value ) );
   }

   /** Sets the value of the EMAIL field of this record to the value 
    *  represented by the parameter <code>PwsPassphrase</code>.
    *  A passphrase of length zero is equivalent to <b>null</b>.
    *  Use <b>null</b> to clear the field.
    */
   public void setEmail ( PwsPassphrase value )
   {
      if ( voidPassphrase( value ) )
         value = null;
      controlValue( email, value, "EMAIL" );
      email = value == null ? null : (PwsPassphrase)value.clone();
   }

   /** Returns the value of the USERNAME field of this record as a String.
    *  Returns <b>null</b> if the field is undefined.
    */
   public String getUsername ()
   {
      return username == null ? null : username.getString();
   }

   /** Returns the value of the USERNAME field of this record as a <code>PwsPassphrase</code>.
    *  Returns <b>null</b> if the field is undefined.
    */
   public PwsPassphrase getUsernamePws ()
   {
      return username == null ? null : (PwsPassphrase)username.clone();
   }

   /** Sets the value of the USERNAME field of this record to the parameter 
    *  <code>String</code> value. An empty string will render equivalent to 
    *  <b>null</b>. Use <b>null</b> to clear the field.
    */
   public void setUsername ( String value )
   {
      value = transformedStringParam( value );
      setUsername( value == null ? null : new PwsPassphrase( value ) );
   }

   /** Sets the value of the USERNAME field of this record to the value 
    *  represented by the parameter <code>PwsPassphrase</code>.
    *  A passphrase of length zero is equivalent to <b>null</b>.
    *  Use <b>null</b> to clear the field.
    */
   public void setUsername ( PwsPassphrase value )
   {
      if ( voidPassphrase( value ) )
         value = null;
      controlValue( username, value, "USERNAME" );
      username = value == null ? null : (PwsPassphrase)value.clone();
   }

   /** This will set PASSMODTIME and ACCESSTIME to the actual time and should 
    *  be called after a password value was modified. 
    *  (For reasons of flexibility this is not automatically called when 
    *  modifying a password through <code>setPassword()</code>.)
    */ 
   public void passwordUpdated ()
   {
      long time = System.currentTimeMillis();
      setPassModTime( time );
      setAccessTime( time );
   }
   
   /** Adds an unknown field value for this record for the purpose of conservation.
    *  In contrast to <code>setExtraField()</code> no validation is performed on the
    *  ID value. Does nothing if <code>value</code> is <b>null</b>.
    *  (This value is stored internally in cleartext during program session.)
    * 
    * @param id field ID number (0..255)
    * @param value field value (exact length)
    * @since 0-4-0
    */
   protected void addUnknownField ( int id, byte[] value )
   {
      if ( value == null )
         return;
      
      if ( otherValues == null )
         otherValues = new RawFieldList();
      
      otherValues.setField( new PwsRawField( id, value ) );
   }
   
   /** Inserts or sets a data field in this record which forms a non-canonical field identified by
    *  its integer type code. Only non-canonical field types may be entered; use the 
    *  <b>null</b> value to clear the field from the list.
    *  <small>Notes: This value is stored internally in cleartext during 
    *  program execution. This method replaces any occurrence of a previously defined field
    *  with type <code>id<code> in the unknown field list. Whether a field value is 
    *  canonical can be tested by <code>PwsFileFactory.isCanonicalField()</code>.</small>
    * 
    * @param id non-canonical field ID number within 0..255
    * @param value field value, or <b>null</b> to remove the field
    * @param format the referenced file format version or 0 for default
    * @since 0-4-0
    * @since 2-0-0 extended
    */
   public void setExtraField ( int id, byte[] value, int format )
   {
      // control field type
      if ( PwsFileFactory.isCanonicalField( id, format ) )
         throw new IllegalArgumentException( "canonical field type" );

      // ensure list instance
      if ( otherValues == null )
         otherValues = new RawFieldList();

      // add / replace new value
      if ( value == null )
      {
         if ( otherValues.removeField( id ) != null )
            modified();
      }
      else
      {
         otherValues.setField( new PwsRawField( id, value ) );
         modified();
      }
   }  // setExtraField
   
   /** Gets an iterator over all unknown fields stored for this record.
    *  
    * @return <code>Iterator</code> of element type <code>PwsRawField</code>
    *         or <b>null</b> if no fields are listed
    * @since 0-4-0 protected
    * @since 2-0-0 public
    */
   public Iterator getUnknownFields ()
   {
      return otherValues == null || otherValues.size() == 0 ? null : otherValues.iterator();
   }
   
   /**
    * Returns the number of datafields which are not canonical in this record.
    * (This includes fields added by <code>setExtraField()</code> method.)
    * @return int
    * @since 2-0-0 
    */
   public int getUnknownFieldCount ()
   {
      return otherValues == null ? 0 : otherValues.size();
   }
   
   /**
    * Returns the size of the data block required to store the content of
    * this record on a persistent state. (This takes into account the general 
    * file formating rules of a PWS file.) 
    * 
    * @param format the file format version of the persistent state
    * @return int required (blocked) data space
    * @throws IllegalCharsetNameException if charset is unknown to the executing VM
    * @since 2-0-0
    */
   public long getBlockedDataSize ( int format, String charset )
   {
      long sum;

      sum = 0;
      
      // constant size consisting of fields:
      switch ( format )
      {
      case Global.FILEVERSION_3:
         sum = fieldBlockSizeUpdate( sum, url, format, charset );
         sum = fieldBlockSizeUpdate( sum, autotype, format, charset );
         sum = fieldBlockSizeUpdate( sum, history, format, charset );
         sum = fieldBlockSizeUpdate( sum, email, format, charset );
         sum = fieldBlockSizeUpdate( sum, autotype, format, charset );
         sum = fieldBlockSizeUpdate( sum, passPolicyName, format, charset );
         sum = fieldBlockSizeUpdate( sum, runCommand, format, charset );
         sum = fieldBlockSizeUpdate( sum, dclickAction, format, charset );
         sum = fieldBlockSizeUpdate( sum, shiftDclickAction, format, charset );
         if ( passPolicy != null ) 
         {
            sum = fieldBlockSizeUpdate( sum, passPolicy.getModernForm(), format, charset );
            if ( passPolicy.hasOwnSymbols() )
               sum = fieldBlockSizeUpdate( sum, new String( passPolicy.getOwnSymbols() ), format, charset );
         }
      
      case Global.FILEVERSION_2:
         sum = fieldBlockSizeUpdate( sum, group, format, charset );
         sum += PwsRawField.pwsFieldBlockSize( 16, format );  // UUID
         if ( format <= Global.FILEVERSION_2 && passPolicy != null )
            sum += PwsRawField.pwsFieldBlockSize( 4, format );  // PassPolicy old format
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
         
      
      case Global.FILEVERSION_1:
         sum = fieldBlockSizeUpdate( sum, title, format, charset );
         sum = fieldBlockSizeUpdate( sum, username, format, charset );
         sum = fieldBlockSizeUpdate( sum, notes, format, charset );
         sum = fieldBlockSizeUpdate( sum, password, format, charset );
      }
      
      // size of extra fields (unknown fields) if present
      if ( otherValues != null )
         sum += otherValues.blockedDataSize( format );
      
      // add space for EOR marker (formats V2 and V3) 
      sum += format == Global.FILEVERSION_1 ? 0 : 16;
      return sum;
   }
   
   /**
    * Helper to calculate <code>getBlockedDataSize()</code>; adds the
    * storable size of a text field, which may be <code>String</code> or 
    * <code>PwsPassphrase</code>. 
    * 
    * @param sum sum so far
    * @param field <code>String</code> or <code>PwsPassphrase</code>
    * @param format format of the persistent state
    * @param charset encoding used on the field's text 
    * 
    * @return sum + size of store data block of the parameter record field
    * @throws IllegalCharsetNameException if charset is unknown to the executing VM
    * @since 2-0-0   
    */
   private long fieldBlockSizeUpdate ( long sum, Object field, int format, String charset )
   {
      byte[] data ;
      
      if ( field != null )
      {
         if ( field instanceof String )
            try { data = ((String)field).getBytes( charset ); }
            catch ( UnsupportedEncodingException e )
            { throw new IllegalCharsetNameException( charset ); }
         else if ( field instanceof PwsPassphrase )
            data = ((PwsPassphrase)field).getBytes( charset );
         else if ( field instanceof PwsRawField )
            data = ((PwsRawField)field).getData();
         else throw new IllegalStateException( "illegal parameter type FIELD" ); 

         sum += PwsRawField.pwsFieldBlockSize( data.length, format );
         Util.destroyBytes( data );
      }
      else if ( format < Global.FILEVERSION_3 )
         sum += 16;

      return sum;
   }
   
   
   /**
    * Returns the total data size of all unknown fields in this record.
    * (This refers to blocked data size according to the specified file format.)
    * @param format the format version of the persistent state to be considered
    * @return long unknown data size
    * @since 2-0-0 
    */
   public long getUnknownFieldSize ( int format )
   {
      return otherValues == null ? 0 : otherValues.dataSize( format );
   }
   
   /**
    * Permanently removes all unknown (or "extra") fields from this record. 
    */
   public void clearExtraFields ()
   {
      if ( otherValues != null )
         otherValues.clear();
   }
   
   /** Returns a copy of a field value from the "unknown" field list of this record 
    *  that matches the given field identity code.
    *  
    * @param id identity of field type (0..255)
    * @return byte[] cleartext field value or <b>null</b> if field is not available
    * @since 0-4-0
    */
   public byte[] getExtraField ( int id )
   {
      PwsRawField fld;
      
      if ( otherValues != null && (fld = otherValues.getField( id )) != null )
         return fld.getData();
      
      return null ; 
   }
   
   /** Returns a normalised version of the parameter String value.
    *  For a value not <b>null</b>: trims the value, and if the result equals
    *  the empty string, the value is transformed into a <b>null</b> value. 
    */ 
   private String transformedStringParam ( String param )
   {
      if ( param != null )
      {
         param = param.trim();
         if ( param.equals("") )
            param = null;
      }
      return param;
   }
   
   /** Opportunity to set an initializing phase for a record. If true,
    *  any field setup will not cause the record modify time (MODIFYTIME) to 
    *  get updated.
    * 
    *  @param b <b>true</b> == init phase active
    */ 
   public void setInitialize ( boolean b )
   {
      initializing = b;
   }
   
   /** Returns the RECORD-ID field of this record as a <code>UUID</code> object.
    */
   public UUID getRecordID ()
   {
      return recordID;
   }

   /** Sets the RECORD-ID field of this record from the parameter <code>UUID</code>
    *  value. Should be used with great care! (This does not update any time fields.)
    *  
    * @param uuid the new Record-ID for this record; must not be <b>null</b>
    * @throws NullPointerException if <code>uuid</code> is <b>null</b>
    */
   public void setRecordID ( UUID uuid )
   {
      UUID old;
      
      if ( uuid == null )
         throw new NullPointerException();
      
      old = recordID; 
      recordID = uuid;
      Log.log( 4, "(PwsRecord) set record-ID to: " + recordID + ", " + old );
   }
   
   /** Returns the import status. If this record was imported by the 
    *  <code>PwsRecordList.merge()</code> method, it will carry one 
    *  of the status values IMPORTED or IMPORTED_CONFLICT.
    * 
    *  @return record's import status (0 for not imported)
    *  @since 0-3-0
    */ 
   public int getImportStatus ()
   {
      return importStatus;
   }
   
   /** Sets the import status of this record.
    *  @since 0-3-0
    *  */
   public void setImportStatus ( int v )
   {
      importStatus = v;
   }
   
/**
 * Whether this record equals to the parameter record object.
 * 
 * @param obj object of type <code>PwsRecord</code> (may be <b>null</b>)
 * @return <b>true</b> if and only if the parameter compare object is not <b>null</b>
 *         and the RECORD-ID fields of both records are equal 
 */
   public boolean equals ( Object obj )
   {
      return obj != null && ((PwsRecord)obj).recordID.equals( recordID );
   }

/** A hashcode value coherent with the <code>equals</code> function.
 */   
   public int hashCode ()
   {
      return recordID.hashCode();
   }

   /**
    * A String representation of this record. Renders the Record-ID.
    * <br>Example/format: "{01234567-89ab-cdef-0123-456789abcdef}" 
    */
   public String toString ()
   {
      return recordID.toString();
   }
   
   /**
    * Returns a CRC checkvalue for the contents of this record.
    * (It may not be assumed that this value is identical over different
    * releases of this software package. It may be assumed that it is identical
    * over different program sessions with the same software package.)
    * 
    * @return CRC32 integer incorporating all variable record elements 
    */
   public int getCRC ()
   {
      ByteArrayOutputStream output;
      DataOutputStream out;
      PwsRawField ufld;
      Iterator it;
      CRC32 crc = new CRC32();
   
      output = new ByteArrayOutputStream();
      out = new DataOutputStream( output );
      
      try {
         out.write( recordID.getBytes() );
   
         if ( password != null )
            // secure integration of a password value crc
            out.writeInt( password.hashCode() );
   
         if ( passPolicy != null )
         {
            out.writeInt( passPolicy.getIntForm() );
            out.writeChars( new String( passPolicy.getActiveSymbols() ));
         }
   
         out.writeLong( accessTime );
         out.writeLong( createTime );
         out.writeLong( modifyTime );
         out.writeLong( passLifeTime );
         out.writeLong( passModTime );
   
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

         if ( (it = getUnknownFields()) != null )
            while ( it.hasNext() )
            {
               ufld = (PwsRawField)it.next();
               out.write( ufld.type );
               out.write( ufld.data );
            }
         out.close();
      }
      catch ( IOException e )
      {
         System.out.println( "*** ERROR in PwsRecord CRC : " + e );
         return -1;
      }
      
      crc.update( output.toByteArray() );
      return (int)crc.getValue();
   }  // getCRC

   /**
    * Renders a unique signature value of this record and its actual data state.
    * Returns a SHA-256 checksum over all data content of this record. (Note that
    * UUID is included in the integration, hence each record is guaranteed an 
    * individual value, regardless of its data content.  
    * It may be assumed - although there is no guarantee - that this value is identical 
    * over different releases of this software package and different sessions of a
    * program running this package.)
    * 
    * @return byte[] 32 byte signature value (SHA-256 digest) 
    * @since 2-0-0
    */
   public byte[] getSignature ()
   {
      ByteArrayOutputStream output;
      DataOutputStream out;
      PwsRawField ufld;
      Iterator it;
      SHA256 sha;

      output = new ByteArrayOutputStream();
      out = new DataOutputStream( output );
      sha = new SHA256();
      
      try {
         out.write( recordID.getBytes() );

         if ( password != null )
            // secure integration of a password value crc
            out.writeInt( password.hashCode() );

         if ( passPolicy != null )
            out.writeInt( passPolicy.getIntForm() );

         out.writeLong( accessTime );
         out.writeLong( createTime );
         out.writeLong( modifyTime );
         out.writeLong( passLifeTime );
         out.writeLong( passModTime );
         out.writeInt( expiryInterval );

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
         if ( (it = getUnknownFields()) != null )
            while ( it.hasNext() )
            {
               ufld = (PwsRawField)it.next();
               out.write( ufld.type );
               out.write( ufld.data );
            }
         out.close();
      }
      catch ( IOException e )
      {
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
 * @since 2-0-0
 */
public String getAutotype ()
{
   return autotype;
}

/**
 * Set the AUTOTYPE text field of this record to the parameter value.
 * <b>null</b> or empty string will clear the field.
 * 
 * @param value String 
 * @since 2-0-0
 */
public void setAutotype ( String value )
{
   String old = autotype;
   autotype = transformedStringParam( value );
   controlValue( old, autotype, "AUTOTYPE" );
}

/**
 *  Content of the password HISTORY textfield as a passphrase.
 *  Returns <b>null</b> if the field is undefined.
 *  
 *  @return <code>PwsPassphrase</code>
 *  @since 2-0-0
 */
public PwsPassphrase getHistoryPws ()
{
   return history == null ? null : (PwsPassphrase)history.clone();
}

/**
 *  Content of the password HISTORY textfield as a text string.
 *  Returns <b>null</b> if the field is undefined.
 * 
 * @return String history value (PW3)
 * @since 2-0-0
 */
public String getHistory ()
{
   return history == null ? null : history.getString();
}

/** Sets the value of the HISTORY field (PW3) of this record to the parameter 
 *  <code>String</code> value. An empty string will render equivalent to 
 *  <b>null</b>. Use <b>null</b> to clear the field.
 *  
 *  @param value String history value (PW3)
 *  @since 2-0-0
 */
public void setHistory ( String value )
{
   value = transformedStringParam( value );
   setHistory( value == null ? null : new PwsPassphrase( value ) );
}

/**
 * Sets the value of the HISTORY field  (PW3) of this record to the value 
 *  represented by the parameter <code>PwsPassphrase</code>.
 *  A passphrase of length zero is equivalent to <b>null</b>.
 *  Use <b>null</b> to clear the field.
 *  
 * @param value <code>PwsPassphrase</code>
 * @since 2-0-0
 */
public void setHistory ( PwsPassphrase value )
{
   if ( voidPassphrase( value ) )
      value = null;
   controlValue( history, value, "HISTORY" );
   history = value == null ? null : (PwsPassphrase)value.clone();
}

/**
 *  Content of the URL textfield as a passphrase.
 *  Returns <b>null</b> if the field is undefined.
 *  
 *  @return <code>PwsPassphrase</code>
 *  @since 2-0-0
*/
public PwsPassphrase getUrlPws ()
{
   return url == null ? null : (PwsPassphrase)url.clone();
}

/**
 *  Content of the URLFIELD textfield as a text string.
 *  Returns <b>null</b> if the field is undefined.
 * 
 * @return String or <b>null</b>
  * @since 2-0-0
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
   value = transformedStringParam( value );
   setUrl( value == null ? null : new PwsPassphrase( value ) );
}

/**
 * Sets the value of the URLFIELD field of this record to the value 
 *  represented by the parameter <code>PwsPassphrase</code>.
 *  A passphrase of length zero is equivalent to <b>null</b>.
 *  Use <b>null</b> to clear the field.
 *  
 * @param value <code>PwsPassphrase</code> containing URL string
 * @since 2-0-0
 */
public void setUrl ( PwsPassphrase value )
{
   if ( voidPassphrase( value ) )
      value = null;
   controlValue( this.url, value, "URLFIELD" );
   this.url = value == null ? null : (PwsPassphrase)value.clone();
}

/**
 * Returns the string expression of the parent group to the
 * given group name or <b>null</b>. 
 * 
 * @param group String correct group name, including empty string,
 *        or <b>null</b>
 * @return group name or <b>null</b> if no parent exists
 */
public static String groupParent ( String group )
{
   if ( group != null && group.length() != 0 )
   {
      int i = group.lastIndexOf('.');
      if ( i > 0 )
         return group.substring(0, i);
   }
   return null;   
}

/** Whether this record bears a protection marker, like e.g.
 * for a read-only interpretation.
 * 
 * @return boolean
 */
public boolean isProtectedEntry ()
{
   return protectedEntry;
}

/** Set the "Protected Entry" marker for this record.
 * 
 * @param protectedEntry boolean <b>true</b> == protected entry
 */
public void setProtectedEntry ( boolean protectedEntry )
{
   boolean oldValue = this.protectedEntry;
   
   this.protectedEntry = protectedEntry;
   controlValue( new Boolean(oldValue), new Boolean(protectedEntry), "PROTECTED_ENTRY" );
}

/** If the password policy for this record was set by a policy name
 * (in contrast to the policy directly) then the name is returned here,
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
 * The name here, however, can be supplied freely.)
 *  
 * @param policyName String policy name
 */
public void setPassPolicyName ( String policyName )
{
   String oldValue = this.passPolicyName;
   this.passPolicyName = policyName;
   controlValue( oldValue, policyName, "PASSPOLICY_NAME" );
}

}
