/*
 *  Newclass in org.jpws.data
 *  file: DefaultRecordWrapper.java
 * 
 *  Project Jpws-Front
 *  @author Wolfgang Keller
 *  Created 10.08.2005
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
 * sort value is not recalculated except through the use of <code>refresh()</code>.
 * The general practice is to substitute wrappers of a record by a new instance
 * whenever a permanent modification occurs on the referenced record's content. 
 * 
 * @since 0-3-0
 */
public class DefaultRecordWrapper implements Comparable, Collatable, Cloneable
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
     * @since 2-1-0
     */
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
     * @return array of DefaultRecordWrapper or <b>null</b>
     * @since 2-1-0
     */
    public static DefaultRecordWrapper[] makeWrappers ( PwsRecord[] recs, Locale loc )
    {
       DefaultRecordWrapper[] result;
       int i;
       
       if ( recs == null )
          return null;
       
       result = new DefaultRecordWrapper[ recs.length ]; 
       for ( i = 0; i < recs.length; i++ )
          result[ i ] = new DefaultRecordWrapper( recs[ i ], loc );
       return result;
    }

   /** Recalculates the expiry status of this record according to actual 
    *  compare values.
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
      if ( locale != null )
         key = Collator.getInstance( locale ).getCollationKey( sortValue );
   }
   
   /** Sets a locale for the sort value of this wrapper. This determines the
    *  value of the collation key.
    * 
    *  @param l locale to be activated for the collation key
    */
   public void setLocale ( Locale l )
   {
      if ( l == null )
         l = Locale.getDefault();
      
      if ( !l.equals( locale ) )
      {
         locale = l;
         key = Collator.getInstance( locale ).getCollationKey( sortValue );
      }
   }
   
   /** Returns the Locale used in this record wrapper for collating. 
    * @since 2-1-0
    */
   public Locale getLocale ()
   {
      return locale;
   }
   
   /** Returns the standard sortvalue of the parameter record.
    *  This is a concatenation of group and title fields. */
   public static String sortValueOf ( PwsRecord rec )
   {
      return sortValueOf( rec.getGroup(), rec.getTitle() );
   }
   
   /** Returns the standard sortvalue given
    *  the parameter group and title values. */
   public static String sortValueOf ( String group, String title )
   {
      if ( group == null )
         group = "";
      if ( title == null )
         title = "";
      return group + ":" + title;
   }
   
   /**
    * Makes a deep clone of an array of DefaultRecordWrapper items.
    * 
    * @param arr <code>DefaultRecordWrapper[]</code>
    * @return <code>DefaultRecordWrapper[]</code> deep clone of parameter
    * @since 0-6-0
    */
   public static DefaultRecordWrapper[] cloneArray ( DefaultRecordWrapper[] arr )
   {
      DefaultRecordWrapper[] res;
      int i;
      
      res = new DefaultRecordWrapper[ arr.length ];
      for ( i = 0; i < arr.length; i++ )
         res[ i ] = (DefaultRecordWrapper)arr[ i ].clone();
      return res;
   }
   
	/**
	 * Returns the record contained in this record-wrapper (direct reference).
	 * @return <code>PwsRecord</code>
	 */
	public PwsRecord getRecord()
	{
		return record;
	}

    /**
     * Returns the UUID value of the record contained in this wrapper.
     * @return <code>PwsRecord</code>
     * @since 2-1-0
     */
    public UUID getRecordID()
    {
        return record.getRecordID();
    }

   /**
    * Returns the GROUP field value of the record. Other than at the record directly, 
    * a void value results in an empty string.
    * 
    * @return String record GROUP value or empty string 
    */
   public String getGroup()
   {
      String hstr;
      
      hstr = record.getGroup();
      return hstr == null ? "" : hstr;
   }

   /** Expire status of this record. Returns 0 if not expired.
    * 
    * @return one of { 0, EXPIRED, EXPIRE_SOON }
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
   public boolean equals ( Object obj )
   {
      return obj != null && 
             ((DefaultRecordWrapper)obj).getRecord().equals( record );
   }

   /** Wrappers compare to each other along their record sort-values. 
    * 
    * @param obj a <code>DefaultRecordWrapper</code> object
    * @return int compare result 
    */
   public int compareTo ( DefaultRecordWrapper obj )
   {
      return key.compareTo( obj.key );
   }
   
   /** Wrappers compare to each other along their record sort-values.
    * 
    * @param obj a <code>DefaultRecordWrapper</code> object
    * @return int compare result 
    */
   public int compareTo ( Object obj )
   {
      return compareTo( (DefaultRecordWrapper)obj );
   }
   
   /** Returns the sort-value of the record. */
	public String getSortValue ()
   {
	   return sortValue;
   }

   /** <code>equals()</code> compatible hashcode. */
   public int hashCode ()
   {
      return record.hashCode();
   }
   
   /** Returns the collation key representing the sort value of this wrapper.
    *  The collation key is valid relative to the Locale set up for this wrapper.
    */
   public CollationKey getCollationKey ()
   {
      return key;
   }
   
   /**
	 *  The displayable title of the contained record. Consists of the TITLE
    *  field plus, if opted in program options, the USERNAME field.
    *  The result of this is depending on the value of <code>Global.isDisplayUsernames()
    *  </code>.
	 * 
	 * @return title String
	 */
	public String toString()
	{
	   String title, username;
      
      username = record.getUsername();
      if ( (title = record.getTitle()) == null )
         title = defaultTitle;
		return username == null || !Global.isDisplayUsernames() ? 
             title : title + " [" + username + "]";
	}
    
   /** Sets the index position belonging to a sorted order. (Informational) */  
   void setIndex ( int i )
   {
      index = i;
   }
   
   /** Returns the index position information belonging to a sorted order.
    *  This is only a procedural information and not of validity to the public! 
    *  */  
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
      if ( !cs )
         for ( i = 0; i < domain.length; i++ )
            domain[i] = Character.toLowerCase( domain[i] );
      
      // investigate domain for matching pattern
      slen = domain.length - pattern.length + 1;
      for ( i = 0; i < slen; i++ )
      {
      
         found = true;
         for ( j = 0; j < pattern.length; j++ )
            if ( domain[ i+j ] != pattern[ j ] )
            {
               found = false;
               break;
            }

         if ( found )
         {
            if ( wd )
            {
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
 * @param text search text
 * @param cs whether search is case sensitive
 * @param wd whether search looks for whole words only
 * @return <b>true</b> if and only if the search text is contained in 
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
      if ( (pass = record.getUsernamePws()) != null )
      {
         buf = pass.getValue();
         check = textMatch( buf, pat, cs, wd );
         Util.destroyChars( buf );
         if ( check )
            return true;
      }
      
      // NOTES
      if ( (pass = record.getNotesPws()) != null )
      {
         buf = pass.getValue();
         check = textMatch( buf, pat, cs, wd );
         Util.destroyChars( buf );
         if ( check )
            return true;
      }
      
      // URL
      if ( (pass = record.getUrlPws()) != null )
      {
         buf = pass.getValue();
         check = textMatch( buf, pat, cs, wd );
         Util.destroyChars( buf );
         if ( check )
            return true;
      }
      
      // EMAIL
      if ( (pass = record.getEmailPws()) != null )
      {
         buf = pass.getValue();
         check = textMatch( buf, pat, cs, wd );
         Util.destroyChars( buf );
         if ( check )
            return true;
      }
      
      return false;
   }
}
