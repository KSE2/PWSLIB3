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

   /** May be set by the application to allow improved "toString()" output.
    *  This content is used when the record field TITLE is void. 
    *  Defaults to "?" 
    */
   public static String defaultTitle = "?";
   
   private Locale locale;
   private CollationKey key;
   
   private PwsRecord	record;
   private String sortValue;
   private int index = -1;
   private int expiry;
   private int importry;;

	/**
	 * Constructor completely defining this record representation.
     * (The parameter object is used in direct reference.) 
     * 
	 * @param rec the record to be represented 
     * @param loc the locale used for sorting this instance; if <b>null</b>
     *        the current VM default locale is used
	 */
	public DefaultRecordWrapper( PwsRecord rec, Locale loc )
	{
       if ( rec == null )
          throw new NullPointerException( "record void" );
       
      record	= rec;
      refresh();
      setLocale( loc );
   }

    /**
     * Makes a deep clone of this wrapper object.
     */
    @Override
	public Object clone ()
    {
       DefaultRecordWrapper obj;
       
       try { obj = (DefaultRecordWrapper) super.clone(); }
       catch ( CloneNotSupportedException e )
       { return null; }
       
       obj.record = (PwsRecord) record.clone();
       obj.key = Collator.getInstance( locale ).getCollationKey( sortValue );
       return obj;
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
    public static DefaultRecordWrapper[] makeWrappers (PwsRecord[] recs, Locale loc)
    {
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
   public void refreshExpiry ( long expireScope )
   {
      expiry = record.hasExpired() ? EXPIRED :
         record.willExpire( System.currentTimeMillis() + expireScope ) ? 
         EXPIRE_SOON : 0;
   }
   
   /** Refreshes all derived values of this wrapper from the underlying
    *  record value. Note that Expiry is recalculated by this with the
    *  standard scope of <code>Global.DEFAULT_EXPIRESCOPE</code>.
    *
    */
   public void refresh ()
   {
      sortValue = sortValueOf( record );
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
   public void setLocale ( Locale l )
   {
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
   public Locale getLocale ()
   {
      return locale;
   }
   
   /** Returns the standard sort value of the parameter record.
    *  This is a concatenation of group and title fields.
    *  
    *  @param rec <code>PwsRecord</code>
    *  @return String record sort value
    */
   public static String sortValueOf ( PwsRecord rec )
   {
      return sortValueOf( rec.getGroup(), rec.getTitle() );
   }
   
   /** Returns the standard sort value given the parameter group and title 
    * values.
    * 
    *  @return String sort value, combination of parameters 
    */
   public static String sortValueOf ( String group, String title )
   {
      if ( group == null )
         group = "";
      if ( title == null )
         title = "";
      return group + ":" + title;
   }
   
   /**
    * Makes a deep clone of an array of <code>DefaultRecordWrapper</code> items.
    * 
    * @param arr <code>DefaultRecordWrapper[]</code>
    * @return <code>DefaultRecordWrapper[]</code> deep clone of parameter
    */
   public static DefaultRecordWrapper[] cloneArray ( DefaultRecordWrapper[] arr )
   {
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
	public PwsRecord getRecord()
	{
		return record;
	}

    /**
     * Returns the UUID value of the record contained in this wrapper.
     * 
     * @return <code>UUID</code> record UUID
     */
    public UUID getRecordID()
    {
        return record.getRecordID();
    }

   /**
    * Returns the GROUP field value of the record. Other than at the record 
    * directly, a void value results in an empty string.
    * 
    * @return String record GROUP value or empty string 
    */
   public String getGroup()
   {
      String hstr = record.getGroup();
      return hstr == null ? "" : hstr;
   }

   /** Expire status of this record. Returns 0 if not expired.
    * 
    * @return int, one of { 0, EXPIRED, EXPIRE_SOON }
    */
   public int getExpiry ()
   {
      return expiry;
   }
   
   /** Import status of this record. Returns 0 if not imported.
    * 
    * @return one of { 0, IMPORTED, IMPORTED_CONFLICT }
    */
   public int getImportStatus ()
   {
      return importry;
   }
   
   /** Wrappers equal parallel to their contained records. */ 
   @Override
   public boolean equals ( Object obj )
   {
      return obj != null && 
             ((DefaultRecordWrapper)obj).getRecord().equals( record );
   }

   /** <code>equals()</code> compatible hashcode. */
   @Override
   public int hashCode ()
   {
      return record.hashCode();
   }
   
   /** Wrappers compare to each other along their record sort-values. 
    * 
    * @param obj a <code>DefaultRecordWrapper</code> object
    * @return int compare result 
    */
   @Override
   public int compareTo ( DefaultRecordWrapper obj )
   {
      return key.compareTo( obj.key );
   }
   
//   /** Wrappers compare to each other along their record sort-values.
//    * 
//    * @param obj a <code>DefaultRecordWrapper</code> object
//    * @return int compare result 
//    */
//   public int compareTo ( Object obj )
//   {
//      return compareTo( (DefaultRecordWrapper)obj );
//   }
   
   /** Returns the sort-value of the record. */
	public String getSortValue ()
   {
	   return sortValue;
   }

   /** Returns the collation key representing the sort value of this wrapper.
    *  The collation key is valid relative to the Locale set up for this wrapper.
    */
   @Override
   public CollationKey getCollationKey ()
   {
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
	public String toString()
	{
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
   void setIndex ( int i )
   {
      index = i;
   }
   
   /** Returns the index position information belonging to a sorted order.
    *  This is only a procedural information and not of validity to the public! 
    */  
   int getIndex ()
   {
      return index;
   }
   
   private boolean isBoundingChar ( char c )
   {
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
         if ( check )
            return true;
      }
      
      // NOTES
      if ( (pass = record.getNotesPws()) != null ) {
         buf = pass.getValue();
         check = textMatch( buf, pat, cs, wd );
         Util.destroyChars( buf );
         if ( check )
            return true;
      }
      
      // URL
      if ( (pass = record.getUrlPws()) != null ) {
         buf = pass.getValue();
         check = textMatch( buf, pat, cs, wd );
         Util.destroyChars( buf );
         if ( check )
            return true;
      }
      
      // EMAIL
      if ( (pass = record.getEmailPws()) != null ) {
         buf = pass.getValue();
         check = textMatch( buf, pat, cs, wd );
         Util.destroyChars( buf );
         if ( check )
            return true;
      }
      
      return false;
   }
}
