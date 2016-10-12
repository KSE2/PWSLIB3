/*
 *  File: DefaultRecordWrapper.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 10.08.2005
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

package org.jpws.pwslib.order;

import java.text.CollationKey;
import java.text.Collator;
import java.util.Locale;

import org.jpws.pwslib.crypto.SHA1;
import org.jpws.pwslib.data.PwsPassphrase;
import org.jpws.pwslib.data.PwsRecord;
import org.jpws.pwslib.global.Global;
import org.jpws.pwslib.global.UUID;
import org.jpws.pwslib.global.Util;

/**
 * This class wraps a <code>PwsRecord</code> for purposes of quick reference
 * to a listing sort value derived from and belonging to the record.
 * 
 * <p>Mutability Status: This class walks from the assumption that the
 * record fields constituting the sort value (namely GROUP and TITLE) will
 * not likely change during the lifetime (validity) of an instance. Hence the
 * sort value is not recalculated except through the use of <code>refresh()
 * </code>. The practised strategy is to substitute wrappers of a record by a 
 * new instance whenever a permanent modification occurs on the referenced 
 * record's content. 
 * 
 */
public class DefaultRecordWrapper implements Comparable<DefaultRecordWrapper>, 
             Collatable, Cloneable
{
   /** Expiry status value. */
   public static final int EXPIRED = 1;
   /** Expiry status value. */
   public static final int EXPIRE_SOON = 2;
   /** Import status value. */
   public static final int IMPORTED = 1;
   /** Import status value. */
   public static final int IMPORTED_CONFLICT = 2;
   /** Sort direction Ascending */
   public static final int ASCENDING = 0;
   /** Sort direction Descending */
   public static final int DESCENDING = 1;
   
   
   public enum SortField {group, title, username, email, url, create_tm, modify_tm, 
	                      expire_tm, used_tm, passmod_tm};

   /** May be set by the application to allow improved "toString()" output.
    *  This content is used when the record field TITLE is void. 
    *  Defaults to "?" 
    */
   public static String defaultTitle = "?";
   private static SHA1 sha1 = new SHA1();
   
   private Locale locale;
   private CollationKey key;
   
   private PwsRecord	record;
   private String sortValue;
   private int index = -1;
   private int expiry;
   private int importry;
   private boolean isDecending;
   private SortField sort1, sort2, sort3;

	/**
	 * Constructor completely defining this record representation.
     * (The parameter object is used in direct reference.) 
     * 
	 * @param rec the record to be represented 
     * @param loc the locale used for sorting this instance; if <b>null</b>
     *        the current VM default locale is used
     * @throws NullPointerException if record is null
	 */
	public DefaultRecordWrapper( PwsRecord record, Locale loc ) {
       if ( record == null )
          throw new NullPointerException( "record void" );
       
      this.record = record;
      sort1 = SortField.group;
      sort2 = SortField.title;
      sort3 = SortField.modify_tm;
      refresh();
      setLocale( loc );
   }

    /**
     * Makes a deep clone of this wrapper object.
     */
    @Override
	public Object clone () {
       DefaultRecordWrapper obj;
       
       try { obj = (DefaultRecordWrapper) super.clone(); }
       catch ( CloneNotSupportedException e )
       { return null; }
       
       obj.record = (PwsRecord) record.clone();
//       obj.key = Collator.getInstance( locale ).getCollationKey( sortValue );
       return obj;
    }

    /** Sets the sorting principle for this record-wrapper as a set of 
     * sort fields, ranging from primary to tertiary sort value.
     * 
     * @param primary <code>SortField</code> first ranking sort value
     * @param secondary <code>SortField</code> second ranking sort value
     * @param tertiary <code>SortField</code> third ranking sort value
     */
    public void setSorting ( SortField primary, 
    		                 SortField secondary,
    		                 SortField tertiary ) {
    	
    	// avoid inefficient action
    	if (primary == sort1 && secondary == sort2 && tertiary == sort3) return;
    	
    	sort1 = primary;
    	sort2 = secondary;
    	sort3 = tertiary;
    	refresh();
    }
    
    /** Sets the sorting direction, either ASCENDING or DESCENDING. Default
     * value is ASCENDING.
     * 
     * @param direction int 
     */
    public void setSortDirection (int direction) {
    	isDecending = direction != ASCENDING;
    }
    
    /** Returns the sorting direction, either ASCENDING or DESCENDING. Default
     * value is ASCENDING.
     * 
     * @return direction int 
     */
    public int getSortDirection () {
    	return isDecending ? DESCENDING : ASCENDING;
    }
    
    /**
     * Creates an array of wrappers for a given set of PwsRecord. (Records used
     * in direct reference.) If the parameter <code>recs</code> is <b>null</b>, 
     * <b>null</b> is also returned.
     * 
     * @param recs array of <code>PwsRecord</code>; may be <b>null</b>
     * @param loc Locale used in the wrapper objects; <b>null</b> for VM default
     * @return array of <code>DefaultRecordWrapper</code> or <b>null</b>
     */
    public static DefaultRecordWrapper[] makeWrappers (PwsRecord[] recs, Locale loc) {
       if ( recs == null ) return null;
       
       DefaultRecordWrapper[] result = new DefaultRecordWrapper[ recs.length ]; 
       for ( int i = 0; i < recs.length; i++ ) {
          result[ i ] = new DefaultRecordWrapper( recs[ i ], loc );
       }
       return result;
    }

   /** Recalculates the expiry status of this record according to actual 
    *  compare values.
    *  
    *  @param expireScope long time duration in milliseconds (delta)
    */
   public void refreshExpiry ( long expireScope ) {
      expiry = record.hasExpired() ? EXPIRED :
         record.willExpire( System.currentTimeMillis() + expireScope ) ? 
         EXPIRE_SOON : 0;
   }
   
   /** Refreshes all derived values of this wrapper from the underlying
    *  record value. Note that Expiry is recalculated by this with the
    *  standard scope of <code>Global.DEFAULT_EXPIRESCOPE</code>.
    *
    */
   public void refresh () {
      sortValue = sortValueOf( record, sort1, sort2, sort3 );
      importry = record.getImportStatus();
      refreshExpiry( Global.DEFAULT_EXPIRESCOPE );
      if ( locale != null ) {
         key = Collator.getInstance( locale ).getCollationKey( sortValue );
      }
   }
   
   /** Sets a locale for the sort value of this wrapper. This determines the
    *  value of the collation key.
    * 
    *  @param l locale to be activated for the collation key
    */
   public void setLocale ( Locale l ) {
      if ( l == null ) {
         l = Locale.getDefault();
      }
      
      if ( !l.equals( locale ) ) {
         locale = l;
         key = Collator.getInstance( locale ).getCollationKey( sortValue );
      }
   }
   
   /** Returns the <code>Locale</code> used in this record wrapper for collating.
    * 
    *  @return <code>Locale</code>
    */
   public Locale getLocale () {
      return locale;
   }
   
//   /** Returns the standard sort value of the parameter record.
//    *  This is a concatenation of group and title field.
//    *  
//    *  @param rec <code>PwsRecord</code>
//    *  @return String record sort value
//    */
//   public static String defaultSortValueOf ( PwsRecord rec ) {
//	   String hstr = sortValueOf(rec, SortField.group, SortField.title, null); 
//	   return hstr;
//   }
   
   /** Returns a sort value of the parameter PWS-record reflecting the given
    * keys for sort fields. The keys are values from the ENUM type <code>
    * SortField</code> which defines the set of possible sort fields.
    *  
    *  @param rec <code>PwsRecord</code>
    *  @param primary SortField the primary sort value
    *  @param secondary SortField the secondary sort value, may be null (cond.)
    *  @param tertiary SortField the tertiary sort value,  may be null
    *  @return String record sort value
    */
   public static String sortValueOf ( PwsRecord rec, 
		                              SortField primary,
		                              SortField secondary,
		                              SortField tertiary ) {
	  // control of legitimate null parameters
	  if (primary == null ) 
		  throw new IllegalArgumentException("primary sort field must not be null");
	  if (secondary == null & tertiary != null) 
		  throw new IllegalArgumentException("secondary sort field must not be null if tertiary is given");
	   
      String pri = fieldSortValue(rec, primary);
      String sec = fieldSortValue(rec, secondary);
      String ter = fieldSortValue(rec, tertiary);
      String recid = getRecordIdent(rec);
      String result = pri + ":" + sec + ":" + ter + ":" + recid;
      return result;
   }
   
   /** Returns a specific field sort value for a given PWS-record.
    * 
    * @param rec PwsRecord
    * @param field SortField enum value
    * @return String the field sort value
    */
   private static String fieldSortValue (PwsRecord rec, SortField field) {
	   String v = null;

	   if ( field != null ) {
		  switch (field) {
		  case group:     v = rec.getGroup(); break;
		  case title:     v = rec.getTitle(); break;
		  case username:  v = rec.getUsername(); break;
		  case expire_tm: v = String.valueOf(rec.getPassLifeTime()/1000); break;
		  case modify_tm: v = String.valueOf(rec.getModifiedTime()/1000); break;
		  case email:     v = rec.getEmail(); break;
		  case url:       v = rec.getUrl(); break;
		  case passmod_tm: v = String.valueOf(rec.getPassModTime()/1000); break;
		  case used_tm:   v = String.valueOf(rec.getAccessTime()/1000); break;
		  case create_tm: v = String.valueOf(rec.getCreateTime()/1000); break;
		  }
	   }
	   return v == null ? "" : v;
   }
   
   private static synchronized String getRecordIdent (PwsRecord rec) {
      byte[] uid = rec.getRecordID().getBytes();
      sha1.reset();
      sha1.update(uid);
      sha1.finalize();
      String res = sha1.toString().substring(0, 6);
      return res;
   }

/**
    * Makes a deep clone of an array of <code>DefaultRecordWrapper</code> items.
    * 
    * @param arr <code>DefaultRecordWrapper[]</code>
    * @return <code>DefaultRecordWrapper[]</code> deep clone of parameter
    */
   public static DefaultRecordWrapper[] cloneArray ( DefaultRecordWrapper[] arr ) {
      DefaultRecordWrapper[] res = new DefaultRecordWrapper[ arr.length ];
      for ( int i = 0; i < arr.length; i++ ) {
         res[ i ] = (DefaultRecordWrapper)arr[ i ].clone();
      }
      return res;
   }
   
	/**
	 * Returns the record contained in this record-wrapper (direct reference).
	 * 
	 * @return <code>PwsRecord</code>
	 */
	public PwsRecord getRecord() {
		return record;
	}

    /**
     * Returns the UUID value of the record contained in this wrapper.
     * 
     * @return <code>UUID</code> record UUID
     */
    public UUID getRecordID() {
        return record.getRecordID();
    }

   /**
    * Returns the GROUP field value of the record. Other than at the record 
    * directly, a void value results in an empty string.
    * 
    * @return String record GROUP value or empty string 
    */
   public String getGroup() {
      String hstr = record.getGroup();
      return hstr == null ? "" : hstr;
   }

   /** Expire status of this record. Returns 0 if not expired.
    * 
    * @return int, one of { 0, EXPIRED, EXPIRE_SOON }
    */
   public int getExpiry () {
      return expiry;
   }
   
   /** Import status of this record. Returns 0 if not imported.
    * 
    * @return one of { 0, IMPORTED, IMPORTED_CONFLICT }
    */
   public int getImportStatus () {
      return importry;
   }
   
   /** Wrappers equal parallel to their contained records. */ 
   @Override
   public boolean equals ( Object obj ) {
      return obj != null && obj instanceof DefaultRecordWrapper &&
             ((DefaultRecordWrapper)obj).getRecord().equals( record );
   }

   /** <code>equals()</code> compatible hashcode. */
   @Override
   public int hashCode () {
      return record.hashCode();
   }
   
   /** Wrappers compare to each other along their record sort-values. 
    * 
    * @param obj a <code>DefaultRecordWrapper</code> object
    * @return int compare result 
    */
   @Override
   public int compareTo ( DefaultRecordWrapper obj ) {
	  int v = key.compareTo( obj.key );
      return isDecending ? -v : v;
   }
   
   /** Returns the sort-value of this record-wrapper.
    * 
    *  @return String sort value (variant length)
    */
	public String getSortValue () {
	   return sortValue;
   }

   /** Returns the collation key representing the sort value of this wrapper.
    *  The collation key is valid relative to the Locale set up for this wrapper.
    *  
    *  @return <code>CollationKey</code>
    */
   @Override
   public CollationKey getCollationKey () {
      return key;
   }
   
   /**
    *  The displayable title of the contained record. Consists of the TITLE
    *  field plus, if opted in program options, the USERNAME field.
    *  The result of this is depending on the value of 
    *  <code>Global.isDisplayUsernames()</code>.
	* 
	* @return String title
	*/
	@Override
	public String toString() {
       String username = record.getUsername();
       String title = record.getTitle();
       if ( title == null ) {
         title = defaultTitle;
       }
	   return username == null || !Global.isDisplayUsernames() ? title : 
 		                          title + " [" + username + "]";
	}
    
   /** Sets the index position belonging to a sorted order. (Informational)
    */  
   void setIndex ( int i ) {
      index = i;
   }
   
   /** Returns the index position information belonging to a sorted order.
    *  This is only a procedural information and not of validity to the public! 
    */  
   int getIndex () {
      return index;
   }
   
   private boolean isBoundingChar ( char c ) {
      return !Character.isLetterOrDigit( c );
   }
   
   private boolean textMatch ( char[] domain, char[] pattern,
         boolean cs, boolean wd )
   {
      int i, j, slen;
      boolean found, check;

      // exclude the impossible
      if ( pattern.length > domain.length )
         return false;
      
      // transform domain to lowercase if "case ignore" opted
      if ( !cs ) {
         for ( i = 0; i < domain.length; i++ )
            domain[i] = Character.toLowerCase( domain[i] );
      }
      
      // investigate domain for matching pattern
      slen = domain.length - pattern.length + 1;
      for ( i = 0; i < slen; i++ ) {
      
         found = true;
         for ( j = 0; j < pattern.length; j++ )
            if ( domain[ i+j ] != pattern[ j ] ) {
               found = false;
               break;
            }

         if ( found ) {
            if ( wd ) {
               // left bound
               check = i == 0 || isBoundingChar( domain[i-1] );
               // right bound
               if ( !(check && 
                     (i == slen-1 || isBoundingChar( domain[i+pattern.length] ))) )
                  continue;     
            }
            return true;
         }
      }
      return false;
   }
   
 /** 
 *  Whether this record contains the search text as specified.
 * 
 * @param text String search text
 * @param cs boolean whether search is case sensitive
 * @param wd boolean whether search looks for whole words only
 * @return boolean <b>true</b> if and only if the search text is contained in 
 *         any one text field except the password 
 */
   public boolean hasText ( String text, boolean cs, boolean wd )
   {
      PwsPassphrase pass;
      String hstr;
      char[] buf, pat;
      boolean check;

      // original or standardised pattern
      pat = (cs ? text : text.toLowerCase()).toCharArray();

      // GROUP
      if ( (hstr = record.getGroup()) != null &&
           textMatch( hstr.toCharArray(), pat, cs, wd ) )
         return true;

      // TITLE
      if ( (hstr = record.getTitle()) != null &&
            textMatch( hstr.toCharArray(), pat, cs, wd ) )
         return true;

      // USERNAME
      if ( (pass = record.getUsernamePws()) != null ) {
         buf = pass.getValue();
         check = textMatch( buf, pat, cs, wd );
         Util.destroyChars( buf );
         if ( check ) return true;
      }
      
      // NOTES
      if ( (pass = record.getNotesPws()) != null ) {
         buf = pass.getValue();
         check = textMatch( buf, pat, cs, wd );
         Util.destroyChars( buf );
         if ( check ) return true;
      }
      
      // URL
      if ( (pass = record.getUrlPws()) != null ) {
         buf = pass.getValue();
         check = textMatch( buf, pat, cs, wd );
         Util.destroyChars( buf );
         if ( check ) return true;
      }
      
      // EMAIL
      if ( (pass = record.getEmailPws()) != null ) {
         buf = pass.getValue();
         check = textMatch( buf, pat, cs, wd );
         Util.destroyChars( buf );
         if ( check ) return true;
      }
      
      return false;
   }
}
