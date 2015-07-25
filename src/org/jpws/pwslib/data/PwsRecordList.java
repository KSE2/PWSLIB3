/*
 *  file: PwsRecordList.java
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

import java.nio.charset.IllegalCharsetNameException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

import org.jpws.pwslib.crypto.SHA256;
import org.jpws.pwslib.exception.DuplicateEntryException;
import org.jpws.pwslib.exception.NoSuchRecordException;
import org.jpws.pwslib.global.Log;
import org.jpws.pwslib.global.UUID;
import org.jpws.pwslib.order.DefaultRecordWrapper;
import org.jpws.pwslib.order.OrderedRecordList;

/**
 *  Top level structure of this library to represent a list of PWS records
 *  ({@link PwsRecord}). Each instance carries a unique identifier (UUID)
 *  which is supplied automatically (the value may get altered by
 *  subclasses). <b>Note that this class is not synchronized.</b> If multiple
 *  threads may modify a list instance structurally they MUST synchronize
 *  on the instance or equivalent other object.
 *   
 *  <p>This class issues modification events which are defined by  
 *  {@link PwsFileEvent}. All data of this list is kept in memory,
 *  hence the total amount of processable records might be restricted
 *  depending on the user's runtime environment. 
 *  
 *  <p>Above plain storage of records, and giving a set or records an identity,
 *  this class offers a) operations on the content set (like merge or group 
 *  manipulation), b) buffered storage (returned
 *  objects are clones of the stored objects) and c) some semantical control 
 *  (only valid records may be added or updated). Note: the semantical control
 *  is not complete as records are allowed to be invalid when they are read from
 *  a persistent state. Therefore it should not be assumed that all entries of 
 *  a list of this class are valid records.
 *  
 *  @see PwsFile
 *  @see PwsFileFactory
 *  @see PwsFileListener
 *  @see org.jpws.pwslib.order.OrderedRecordList
 */
public class PwsRecordList implements Cloneable
{
   /** On merge conflict exclude the record.
    *  @since 0-2-0
    *  */
   public static final int MERGE_PLAIN = 0;
   /** On merge conflict include the record if it is modified younger.
    *  @since 0-2-0
    *  */
   public static final int MERGE_MODIFIED = 1;
   /** On merge conflict include the record if password is used younger.
    *  @since 0-2-0
    *  */
   public static final int MERGE_PASSACCESSED = 2;
   /** On merge conflict include the record if password is modified younger.
    *  @since 0-2-0
    *  */
   public static final int MERGE_PASSMODIFIED = 4;
   /** On merge conflict include the record if password lifetime is longer.
    *  @since 0-2-0
    *  */
   public static final int MERGE_EXPIRY = 8;
   /** On merge conflict include the record.
    *  @since 0-2-1
    *  */
   public static final int MERGE_INCLUDE = 16;

   /** Used to give each instance of this class a (transitional) name. */ 
   private static int instanceCounter;

   /** Internal ID number for an instance of this class;
    *  this number is only for testing and logging references.
    *  Draws its value from instanceCounter.
    */
   protected int fileID;

   /** A string representation of the internal ID number. */ 
   protected String idString;
   
   /** List UUID; always mounted by default, but may also come from an external state. 
    * @since 2-0-0
    */
   private UUID  listUUID = new UUID();
   
   /**
	 * Map holding the records that are elements of this list, mapping
     * from UUID into PwsRecord.
	 */
	private TreeMap		    recMap		= new TreeMap();

   /** Event listeners to this list; holds PwsFileListener values.*/
   private ArrayList        listeners  = new ArrayList();
   
	/**
	 * Flag indicating whether the file has been modified since creation or
    * last save.
	 */
	protected boolean			modified    = true;
    
    /**
     * Flag to indicate that no file-events shall be dispatched.
     */
    protected boolean         eventPause;

	/**
	 * Constructs a new, empty PasswordSafe record list.
	 */
	public PwsRecordList()
	{
      initInstance();
	}  // constructor

    /**
     * Constructs a new PasswordSafe record list with an initial
     * record set as given by the parameter record wrapper array. 
     * Duplicate records in the array are silently ignored; no check 
     * for record validity is performed.
     * 
     * @param recs array of <code>DefaultRecordWrapper</code> objects;
     *        may be <b>null</b>
     * @since 0-4-0       
     */
    public PwsRecordList( DefaultRecordWrapper[] recs )
    {
       int i;
       
       initInstance();
       
       if ( recs != null )
       for ( i = 0; i < recs.length; i++ )
          try { addRecord( recs[ i ].getRecord() ); }
          catch ( DuplicateEntryException e )
          {}
    }  // constructor

   /**
     * Constructs a new PasswordSafe record list with an initial
     * record set as given by the parameter record array. 
     * Duplicate records in the array are silently ignored; no check 
     * for record validity is performed.
     * 
     * @param recs array of <code>PwsRecord</code> objects;
     *        may be <b>null</b>
     * @since 0-6-0       
     */
    public PwsRecordList( PwsRecord[] recs )
    {
       this( DefaultRecordWrapper.makeWrappers( recs, null ) );
    }  // constructor

   private void initInstance ()
   {
      fileID = instanceCounter++;
      idString = " (" + fileID + "): ";
      Log.log( 2, "(PwsRecList) new PwsRecordList: ID = " + fileID );
   }  // initInstance
   
   /**
    * Returns the content of this list as an array of (cloned) records.
    * 
    * @return array of <code>PwsRecord</code>
    * @since 2-1-0
    */
   public PwsRecord[] toArray ()
   {
      PwsRecord arr[];
      Iterator it;
      int i;

      arr = new PwsRecord[ recMap.size() ];
      for ( it = recMap.values().iterator(), i = 0; it.hasNext(); i++ )
         arr[ i ] = (PwsRecord) ((PwsRecord)it.next()).clone();
      return arr;
   }
   
   /**
    * Returns the content of this list as an array of 
    * DefaultRecordWrapper (on cloned records).
    * 
    * @param locale <code>Locale</code> to be used by wrappers 
    *        or <b>null</b> for system default
    * @return DefaultRecordWrapper[]
    * @since 2-1-0
    */
   public DefaultRecordWrapper[] toRecordWrappers ( Locale locale )
   {
      return DefaultRecordWrapper.makeWrappers( toArray(), locale );
   }
   
	/**
	* Adds a clone of a semantically valid record to this list. The given record 
    * has to meet the following conditions for being added:
    * a) returns <b>true</b> on its method "isValid()",
    * b) may not already exist as an entry in this list (Record-ID (UUID) is  
    * used for identification).  
    * If one of these conditions is not met, the record will not be added and 
    * an exception is thrown. 
    * 
    * @param rec <code>PwsRecord</code> the record to be added
    * @throws IllegalArgumentException if the record is not valid
    * @throws DuplicateEntryException if the record already exists
    * @since 2-2-0
    */
	public void addRecordValid( PwsRecord rec )
   throws DuplicateEntryException
	{

	   if ( !rec.isValid() )
         throw new IllegalArgumentException( "invalid record: " +
               rec.getInvalidText() + " (cannot be added)" );
      
      addRecordIntern( rec, "(addRecordValid)" );
	}

   /**
    * Adds a record to this list. The condition for adding the record is that
    * its identification (UUID) may not exist already in this list. 
    * 
    * @param rec the record to be added.
    * 
    * @throws IllegalArgumentException if the record has no Record-ID
    * @throws DuplicateEntryException if the record already exists
    * @since 2-2-0 modified validation logic
    */
   public void addRecord( PwsRecord rec )
   throws DuplicateEntryException
   {
      addRecordIntern( rec, "(addRecord)" );
   }

   /**
    * Adds a clone of the parameter record to this list provided its identification
    * is not already contained. This method does not perform any check on semantical 
    * validity of the record.
    * 
    * @param rec record to be inserted
    * @param report logging marker
    * @throws DuplicateEntryException if record-ID already exists
    */
   private void addRecordIntern( PwsRecord rec, String report )
         throws DuplicateEntryException
   {
      PwsRecord copy;
      
      if ( contains( rec ) )
         throw new DuplicateEntryException("double record entry, cannot be added");
   
      copy = (PwsRecord)rec.clone();
      recMap.put( copy.getRecordID(), copy );
      setModified();
      
      if ( Log.getDebugLevel() > 2 )
      Log.debug( 3, "(PwsRecList) record added to list " + report + idString  + rec.toString() 
            + ", entry no. " + (recMap.size()-1) + ", crc=" + rec.getCRC() );
      fireFileEvent( PwsFileEvent.RECORD_ADDED, (PwsRecord)copy.clone() );
   }

   
   /** Adds a list of records into this record list. The first occurrence of a duplicate
    *  entry will break execution of the inclusion.
    * 
    * @param list <code>PwsRecordList</code>
    * @return a reference to this record list
    * @throws DuplicateEntryException
    * @throws IllegalArgumentException if any input record is invalid
    * @since 2-0-0
    * @since 2-1-0 enhanced
    */
   public PwsRecordList addRecordList ( PwsRecordList list ) throws DuplicateEntryException
   {
      Iterator it;
      boolean old;
/*   
      // test for all-valid argument
      for ( it = list.iterator(); it.hasNext(); )
         if ( !((PwsRecord)it.next()).isValid() )
            throw new IllegalArgumentException( "list contains invalid record" );
*/      
      // insert list elements (without issuing file-events)
      old = getEventPause();
      setEventPause( true );
      for ( it = list.iterator(); it.hasNext(); )
         addRecordIntern( (PwsRecord)it.next(), "addRecordList" );
      setEventPause( old );
      return this;
   }  // addRecordList

   /** Removes a list of records from this record list. Does nothing if the 
    * parameter is <b>null</b> and ignores records which are not contained.
    * 
    * @param list <code>PwsRecordList</code>; may be <b>null</b>
    * @return a reference to this record list
    * @since 2-0-0
    * @since 2-1-0 enhanced
    */
   public PwsRecordList removeRecordList ( PwsRecordList list ) 
   {
      Iterator it;
      boolean old;
   
      if ( list != null )
      {
         old = getEventPause();
         
         if ( list.getRecordCount() > 1 )
         {
            // insert list elements (without issuing file-events)
            setEventPause( true );
         }
         
         for ( it = list.iterator(); it.hasNext(); )
            removeRecord( (PwsRecord)it.next() );
         
         setEventPause( old );
      }
      return this;
   }  // removeRecordList

   /**
    * Returns the cut set of this record list with the parameter
    * record list. If the cut set is empty, an empty list is returned.
    * (For identity only UUID of the records is evaluated; the elements
    * of the result list are clones of elements of this list.)
    * 
    * @param list <code>PwsRecordList</code>
    * @return <code>PwsRecordList</code> cut set with parameter list
    * @since 2-1-0
    */
   public PwsRecordList cutSetRecordList ( PwsRecordList list )
   {
      PwsRecordList result;
      PwsRecord rec, recHere;
      Iterator it;

      result = new PwsRecordList();
      for ( it = list.iterator(); it.hasNext(); )
      {
         rec = (PwsRecord)it.next();
         if ( (recHere = getRecord( rec.getRecordID() )) != null )
            try { result.addRecord( recHere ); }
            catch ( DuplicateEntryException e )
            {}  // ignore duplicates
      }
      return result;
   }
   
   /** Updates a list of records in this record list. Unknown 
    *  records of the parameter list are not updated and returned in the
    *  resulting record list. Does nothing if the parameter is <b>null</b>
    *  or the empty list.
    * 
    * @param list <code>PwsRecordList</code> of records to be updated; 
    *        may be <b>null</b>
    * @return <code>PwsRecordList</code> subset of parameter list containing
    *         records which were not updated; <b>null</b> if empty
    * @since 2-0-0
    */
   public PwsRecordList updateRecordList ( PwsRecordList list ) 
   {
      PwsRecordList result;
      PwsRecord rec;
      Iterator it;
      boolean old;

      result = null;
      if ( list != null && list.getRecordCount() > 0 )
      {
         old = getEventPause();
         setEventPause( true );
         
         // insert list elements (without issuing file-events)
         for ( it = list.iterator(); it.hasNext(); )
         {
            rec = (PwsRecord)it.next();
            try { updateRecord( rec ); }
            catch ( NoSuchRecordException e )
            {
               if ( result == null )
                  result = new PwsRecordList();
               try { result.addRecord( rec ); }
               catch ( DuplicateEntryException e1 )
               {}
            }
         }
         
         setEventPause( old );
      }
      return result;
   }  // addRecordList

   /**
    * Updates an existing record in this list. The record to be updated is
    * identified by its Record-ID (UUID). (Note that changes made to records 
    * obtained from this interface will <b>not</b> strike through to the 
    * corresponding list element. Hence the "updateRecord()" functions are the 
    * indicated way to effectively change an existing record in the list.)
    * 
    * @param rec the record to be updated
    * @throws NoSuchRecordException if the parameter record is unknown
    */
   public void updateRecord( PwsRecord rec )
         throws NoSuchRecordException
   {
      PwsRecord oldRec, copy;
      int oldCrc;
      
      oldRec = getRecordIntern( rec.getRecordID() );
      if ( oldRec == null )
         throw new NoSuchRecordException("failed update on record " + rec);
   
      oldCrc = oldRec.getCRC();
      if ( oldCrc != rec.getCRC() )
      {
         copy = (PwsRecord)rec.clone();
         recMap.remove( rec.getRecordID() );
         recMap.put( rec.getRecordID(), copy );
         setModified();
         if ( Log.getDebugLevel() > 2 )
         Log.debug( 3, "(PwsRecordList.updateRecord) record updated in file" + idString  + copy ); 
         fireFileEvent( PwsFileEvent.RECORD_UPDATED, (PwsRecord)copy.clone() );
      }
   }  // updateRecord

   /**
    * Updates an existing valid record in this list. The record to be updated is
    * identified by its Record-ID (UUID). If the record is not valid and exception 
    * is thrown.
    * 
    * @param rec the record to be updated; must be a valid record
    * 
    * @throws IllegalArgumentException if the record is not valid
    * @throws NoSuchRecordException if the parameter record is unknown
    */
   public void updateRecordValid( PwsRecord rec )
         throws NoSuchRecordException
   {
      if ( !rec.isValid() )
         throw new IllegalArgumentException("invalid record, cannot be updated");
      
      updateRecord( rec );
   }  // updateRecord

   /**
	 * Returns the total number of records in this list.
	 * 
	 * @return total number of records in the file
	 */
	public int getRecordCount()
	{
		return recMap.size();
	}

   /**
    * Returns an iterator over all records. Records may be deleted from this list 
    * by calling the <code>remove()</code> method on the iterator. This iterator
    * returns records that are clone copies of the original file records; modified
    * records have to get "updated" by use of the <code>updateRecord()</code> method.
    * This iterator allows concurrent modifications of this list/database (it operates 
    * on a copy of the list structure created when the iterator is invoked).   
    * 
    * @return an <code>Iterator</code> over all records (with a snapshot of the 
    *         list situation at the timepoint of invokation)
    */
   public Iterator iterator()
   {
      return new FileIterator( ((Map)recMap.clone()).values().iterator() );
   }

   /**
    * Returns the total data size of all unknown (non-canonical) fields
    * in this record list. 
    * (This refers to blocked data size according to the specified file format.)
    * 
    * @param format the format version of the persistent state to be considered
    * @return long unknown data size
    * @since 2-0-0 
    */
   public long getUnknownFieldSize ( int format )
   {
      Iterator it;
      long sum;
      
      for ( it = iterator(), sum = 0; it.hasNext(); )
         sum += ((PwsRecord)it.next()).getUnknownFieldSize( format );
      return sum;
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
      Iterator it;
      int count;
      
      for ( it = iterator(), count = 0; it.hasNext(); )
         count += ((PwsRecord)it.next()).getUnknownFieldCount();
      return count;
   }

   /**
    * Clears away all non-canonical fields in this list of records.
    * @since 2-0-0 
    */
   public void clearUnknownFields ()
   {
      PwsRecordList list;
      PwsRecord rec;
      Iterator it;
      
      if ( getUnknownFieldCount() > 0 )
      {
         list = new PwsRecordList();
         for ( it = iterator(); it.hasNext(); )
         {
            rec = (PwsRecord)it.next();
            if ( rec.getUnknownFieldCount() > 0 )
            {
               rec.clearExtraFields();
               try { list.addRecord( rec ); }
               catch ( DuplicateEntryException e )
               {}
            }
         }
         updateRecordList( list ); 
         
         Log.log( 3, "cleared unknown fields in reclist" + idString );
      }
   }

   /**
    * Returns the number of records in the file which belong to the 
    * specified group value, including descendant groups. (Note that
    * this function refers to the same set building principle as 
    * <code>getGroupedRecords()</code>.) 
    * 
    * @param group String GROUP field selection value; may be <b>null</b>
    * @param exact whether elementary group names must match exactly the parameter
    *  
    * @return number of specified grouped records in the file
    * @since 0-4-0 (modified parameter list)
    * @since 2-1-0 (modified parameter logic: group)        
    */
   public int getGrpRecordCount( String group, boolean exact )
   {
      if ( group == null )
         return 0;
      if ( group.length() == 0 )
         return getRecordCount();
      return new GroupFileIterator( group, exact ).grpList.size();
   }

   /**
    * Returns an iterator over all records whose group value matches with the
    * parameter value. Two modi operandi are possible: relaxed and exact. In 
    * exact mode the parameter value must be identical with an <b>elementary group
    * name</b> in the record group value. In relaxed mode it suffices that the record
    * value starts with the parameter value. Comparison is case sensitive.
    * <p><u>Example</u>: Parameters <code>"AA.Miriam.Car",true</code> will return all
    * records belonging to a group with this name, including all subgroups, but it
    * will not return a record of the "AA.Miriam.Carfesh" group. In relaxed mode
    * the records of the latter group are also returned. 
    * 
    * <p>If <code>group</code> is the empty name, the returned iterator encompasses 
    * all records of this list. If group is <b>null</b> the iterator is empty.
    * 
    * <p>Records may be deleted from the file by calling the <code>remove()</code> 
    * method of the iterator.
    * 
    * @param group String GROUP field selection value; may be <b>null</b>
    * @return an <code>Iterator</code> of elements of type <code>PwsRecord</code>
    * @since 0-4-0 (modified parameter list)
    * @since 2-1-0 (modified parameter logic: group)        
    */
	public Iterator getGroupedRecords ( String group, boolean exact )
   {
      return new GroupFileIterator( group, exact );
   }
   
   /**
    * Returns the number of records which are expired on the date given.
    * 
    * @param date the epoch timepoint for this evaluation
    * @return number of expired records for <code>date</code>
    * @since 0-3-0
    */
   public int countExpired ( long date )
   {
      Iterator it;
      int count;
      
      count = 0;
      for ( it = recMap.values().iterator(); it.hasNext(); )
         if ( ((PwsRecord)it.next()).willExpire( date ) )
            count++;
      return count;
   }

   /**
    * Returns the number of invalid records.
    * 
    * @return number of invalid records
    * @since 2-2-0        
    */
   public int countInvalid ()
   {
      Iterator it;
      int count;
      
      count = 0;
      for ( it = recMap.values().iterator(); it.hasNext(); )
         if ( !((PwsRecord)it.next()).isValid() )
            count++;
      return count;
   }

   /**
    * Removes all invalid records from this list and returns them
    * as a separate record list.
    * 
    * @return <code>PwsRecordList</code> list of invalid records
    *         or <b>null</b> if no invalid records were inheld
    * @since 2-2-0        
    */
   public PwsRecordList clearInvalidRecs ()
   {
      PwsRecordList list = null;
      PwsRecord rec;
      Iterator it;
      
      for ( it = recMap.values().iterator(); it.hasNext(); )
         if ( !(rec = (PwsRecord)it.next()).isValid() )
         {
            if ( list == null )
               list = new PwsRecordList();
            try { 
               list.addRecordIntern( rec, "(clearInvalidRecs)" );
               this.removeRecord( rec );
            }
            catch ( DuplicateEntryException e )
            {}
         }
      return list;
   }
   
   /**
    * Whether this database has invalid records.
    * @since 2-2-0        
    */
   public boolean hasInvalidRecs ()
   {
      return countInvalid() > 0;
   }
   
   /**
    * Renames the GROUP name of a set of records. The set of records is selected
    * by the parameter <code>group</code> as if through <code>getGroupedRecords(group,true)</code>.
    * For each record of the group, the <b>elementary group name</b> part which is defined by 
    * <code>group</code> is replaced by the string <code>newGroup</code>.  
    * <p>!!Note!! This is very powerful and you can relocate this group to a completely 
    * different place in the group tree! 
    * 
    * @param group String as a record group definiens 
    * @param newGroup String that replaces the <code>group</code> text in the records'
    *        GROUP field
    * @return <code>PwsRecordList</code> a list of the records actually modified by this 
    *         operation        
    * @since 0-4-0
    * @since 2-1-0 return type (record list), event org
    */
   public PwsRecordList renameGroup ( String group, String newGroup )
   {
      PwsRecordList list;
      PwsRecord rec;
      Iterator it;
      String grp, hstr;
      boolean old;
      
      old = getEventPause();
      setEventPause( true );

      list = new PwsRecordList();
      for ( it = getGroupedRecords( group, true ); it.hasNext(); )
      {
         rec = (PwsRecord) it.next();
         grp = rec.getGroup();
         hstr = newGroup;
         if ( grp.length() > group.length() )
            hstr += grp.substring( group.length() );
         rec.setGroup( hstr ); 
         try { 
            updateRecord( rec ); 
            try { list.addRecordIntern( rec, "* internal rename group *" ); }
            catch ( Exception e )
            {}
         }
         catch ( NoSuchRecordException e )
         {
            throw new IllegalStateException( "PWSLIB renameGroup():\r\n" + e );
         }
      }

      setEventPause( old );
      return list;
   }  // renameGroup

   /**
    * Deletes a set of records which is defined by the <code>group</code> parameter.
    * This affects all records which belong to the specified <b>elementary group name</b>.
    * <p>(The set of deleted records is equivalent to <code>
    * getGroupedRecords( group, true )</code>). 
    *   
    * @param group String an elementary group name (of the record GROUP field)  
    * @since 0-4-0
    */
   public void removeGroup ( String group )
   {
      boolean oldEvtPause;
      
      oldEvtPause = getEventPause();
      setEventPause( true );
      for ( Iterator it = getGroupedRecords( group, true ); it.hasNext(); )
      {
         it.next();
         it.remove();
      }
      setEventPause( oldEvtPause );
   }
   
   /** Adds the parameter parent expression to the given list
    * and analyses and adds all predecessor group names of parent.
    * 
    * @param list ArrayList of Strings
    * @param parent String, group name, may be <b>null</b>
    */
   private void addParentGroupNames ( ArrayList list, String parent )
   {
      // analyse parent of parent and recurse 
      String pp = PwsRecord.groupParent( parent );
      if ( pp != null )
         addParentGroupNames( list, pp );
      
      // try add parent
      if ( !list.contains( parent ) )
         list.add( parent );
   }

   /** Returns an ordered list of the GROUP field values of this record list
    *  where each group name only shows once. (Ordering follows collation rules
    *  of the actual VM default locale.)
    *  The empty group name is considered a possible element. If this record-list
    *  is empty, an empty list is returned.
    *  
    *  @return java.util.List of strings
    *  @since 0-4-0
    */
   public List getGroupList ()
   {
      OrderedRecordList recList;
      ArrayList list;
      String group, parent, p=null;
      int i;

      list = new ArrayList();
      recList= new OrderedRecordList( this );
      recList.loadDatabase( this, 0 );
      for ( i = 0; i < recList.size(); i++ )
      {
         group = recList.getItemAt( i ).getRecord().getGroup();
         
         // allow empty group as element
         if ( group == null )
            group = "";

         // add parent group names
         parent = PwsRecord.groupParent( group );
         if ( parent != null && !parent.equals(p) )
         {
            addParentGroupNames( list, parent );
            p = parent;
         }

         // add group name if not contained
         if ( !list.contains( group ) )
            list.add( group );
      }
      
      removeFileListener( recList );
      return list;
   }
   
   /** 
    * Returns the number of distinct and used group names in the file.
    * The empty group name is considered a possible element.
    * 
    * @return int number of distinct groups
    * @since 2-0-0
    */
   public int getGroupCount ()
   {
      HashMap map;
      Iterator it;
      String grpval;
      
      map = new HashMap( Math.max( getRecordCount(), 32 ) );
      for ( it = iterator(); it.hasNext(); )
      {
         grpval = ((PwsRecord)it.next()).getGroup();
         map.put( grpval, null );
      }
      return map.size();
   }
   
   /**
	 * Whether this list or any of its records have been modified.
	 * 
	 * @return <code>true</code> if and only if the content of this list has been
    *         modified since the last save or load
	 */
	public boolean isModified()
	{
		return modified;
	}

	/**
	 * Deletes the specified record from this list.
    * Does nothing if the record is not contained in the list
    * or the parameter is void.
    * (A record is identified by its Record-ID (UUID).)
	 * 
	 * @param rec the record to be deleted (may be <b>null</b>)
	 */
	public void removeRecord( PwsRecord rec )
	{
		if ( contains( rec ) )
		{
			recMap.remove( rec.getRecordID() );
			setModified();
         if ( Log.getDebugLevel() > 2 )
         Log.debug( 3, "record removed from list" + idString  + rec.toString() ); 
            fireFileEvent( PwsFileEvent.RECORD_REMOVED, rec );
		}
	}

    /**
    * Deletes the specified record from this list.
    * Does nothing if the record is not contained in this list.
    * (A record is identified by its Record-ID (UUID).)
    * 
    * @param recID the UUID identification of the record to be deleted
    *        (may be <b>null</b>)
    * @since 0-4-0
    */
    public void removeRecord( UUID recID )
    {
       PwsRecord rec;
       
       if ( (rec = getRecordIntern( recID )) != null )
          removeRecord( rec );
    }

   /** Whether the specified record exists in this list.
    * 
    *  @return <b>true</b> if and only if <code>rec</code> is not <b>null</b> and 
    *          a record with the identification (UUID) of the parameter record 
    *          exists in this list
    */
   public boolean contains ( PwsRecord rec )
   {
      return rec == null ? false : recMap.containsKey( rec.getRecordID() );
   }
   
   /** Whether a record with the specified Record-ID (UUID) exists in this list.
    * 
    *  @return <b>true</b> if and only if <code>recID</code> is not <b>null</b> and
    *          a record with the given Record-ID exists in this list
    */
   public boolean contains ( UUID recID )
   {
      return recID == null ? false : recMap.containsKey( recID );
   }

   /** Whether the specified group path exists in this list as a full group name.
    * 
    *  @return <b>true</b> if and only if there exists at least one record with 
    *          a GROUP value that starts with the parameter group name 
    *          (assuming it to be a complete elemental group name)
    * @since 0-4-0
    */
   public boolean containsGroup ( String group )
   {
      Iterator it;
      String hstr;
      int len;
      
      group = PwsRecord.groupNormalized( group );
      len = group.length();
      for ( it = recMap.values().iterator(); it.hasNext(); )
      {
         hstr = ((PwsRecord)it.next()).getGroup();
         if ( hstr != null && hstr.startsWith( group ) &&
              (hstr.length() == len || hstr.charAt( len ) == '.') )
            return true;
      }
      return false;
   }
   
   /**
    * Returns the record with the specified Record-ID as direct reference
    * to internal storage.
    * 
    * @param recID the Record-ID of the requested record (may be <b>null</b>)
    * @return the requested <code>PwsRecord</code> or <b>null</b> if the record 
    *         is unknown in this file
    * @since 0-4-0        
    */
   protected PwsRecord getRecordIntern ( UUID recID )
   {
      return recID == null ? null : (PwsRecord)recMap.get( recID );
   }
   
   /**
    * Returns the record with the specified Record-ID as a clone of
    * the stored record of this list.
    * 
    * @param recID the Record-ID of the requested record
    * @return the requested <code>PwsRecord</code> or <b>null</b> if the record 
    *         is unknown in this file
    */
   public PwsRecord getRecord ( UUID recID )
   {
      PwsRecord rec;
       
      if ( (rec = getRecordIntern( recID )) != null )
         rec = (PwsRecord)rec.clone();
      return rec;
   }
   
   /**
    * Returns the size of the data block required to store the content of
    * this record list on a persistent state. (This takes into respect the 
    * general file formating rules of a PWS file of the specified format.) 
    * 
    * @param format the file format version of the persistent state
    * @param charset encoding used on text data of the contained records 
    * @return long required (blocked) data space
    * @throws IllegalCharsetNameException if charset is unknown to the executing VM
    * @since 2-0-0
    */
   public long getBlockedDataSize ( int format, String charset )
   {
      Iterator it;
      long sum;
      
      // constant size consisting of header and trailer data
      sum = 0;

      // record sum-up
      for ( it = iterator(); it.hasNext(); )
         sum += ((PwsRecord)it.next()).getBlockedDataSize( format, charset );
      
      return sum;
   }

   /**
    * Renders a content signature value for this list of records.
    * Returns a SHA-256 checksum which is a sum-up of all its records' signatures. 
    * Note that this value is not strictly individual for a given instance because 
    * two lists with identical records (or empty) will have the same signature value.
    * (It may be assumed - although there is no guarantee - that this value is identical 
    * over different releases of this software package and different sessions of a
    * program running this package.)
    * 
    * @return byte[] 32 byte signature value (SHA-256 digest) 
    * @since 2-0-0
    */
   public byte[] getSignature ()
   {
      SHA256 sha;
      Iterator it;
      
      sha = new SHA256();
      for ( it = recMap.values().iterator(); it.hasNext();  )
         sha.update( ((PwsRecord)it.next()).getSignature() );
      
      return sha.digest();
   }
   
	/** Removes all records from this list / file.
    */
   public void clear ()
   {
      int size;
      
      if ( (size = getRecordCount()) > 0 )
      {
         recMap.clear();
         setModified();
   
         Log.debug( 3, "clear, all records removed in list" + idString  + size );
         fireFileEvent( PwsFileEvent.LIST_CLEARED, null );
      }
   }
   
   /**
    * Returns a shallow clone of this record list (PwsRecordList). 
    * File-ID number is modified to be unique and any 
    * registered listeners are removed from the clone. 
    * 
    * @return object of type <code>PwsRecordList</code> 
    * @since 2-1-0
    */
   public Object clone ()
   {
      PwsRecordList list;
      
      try { list = (PwsRecordList) super.clone(); }
      catch ( CloneNotSupportedException  e ) 
      { return null; }
   
      list.recMap = (TreeMap) recMap.clone();
      list.listeners  = new ArrayList();
      list.fileID = instanceCounter++;
      list.idString = " (" + list.fileID + "): ";
      list.modified = true;
      Log.log( 2, "(PwsRecList) new PwsRecordList (clone of " + idString + 
               "): ID = " + list.fileID );
      
      return list;
   }

   /**
    * Returns a deep clone of this record list (all records
    * of the returned list are copies of the original).  
    * File-ID number is modified to be unique and any 
    * registered listeners are removed from the clone. 
    * 
    * @return object of type <code>PwsRecordList</code> 
    * @since 2-1-0
    */
   public Object copy ()
   {
      PwsRecordList list;
      Iterator it;
      
      list = (PwsRecordList) clone();

      try {
         list.clear();
         for ( it = iterator(); it.hasNext(); )
            list.addRecord( (PwsRecord)it.next() );
      }
      catch ( Exception e )
      {
         throw new IllegalStateException( "list copy error: " + e.getMessage() );
      }
      
      Log.log( 2, "(PwsRecList) create copy of PwsRecordList " + idString + 
               ": ID = " + list.fileID );
      return list;
   }
   
   /**
    * This method replaces entire content of this record list, including most settings,
    * by the contents of the parameter record list. (This list keeps its original
    * fileID number, thus making it different from the parameter list, but it takes over
    * the other list's listUUID. The fileID, however, is only used for testing causes.)
    * For any operational businesses, this list will have the identity of the parameter list
    * and work as a shallow clone.
    *   
    * @param a <code>PwsRecordList</code> new content and identity for this list
    */
   public void replaceFrom ( PwsRecordList a )
   {
      modified = a.modified;
      listeners = (ArrayList)a.listeners.clone();
      listUUID = a.listUUID;
      recMap = (TreeMap)a.recMap.clone();
   }
   
	/**
	 * Sets the flag to indicate that the list of records has been modified.  
     * (There should not normally be any reason to call this method as it 
     * should be called indirectly when a record is added, changed or removed.)
	 */
	protected void setModified()
	{
		modified = true;
	}

   /**
    * Resets the modified flag to <b>false</b>.
    */
   public void resetModified()
   {
      modified = false;
   }

   /**
    * Adds a <code>PwsFileListener</code> to this list of records.
    * @param listener
    */
   public void addFileListener ( PwsFileListener listener )
   {
      if ( listener != null && !listeners.contains( listener ) )
      synchronized ( listeners )   
         { listeners.add( listener ); }
   }
   
   /**
    * Removes a <code>PwsFileListener</code> from this list of records.
    * @param li the <code>PwsFileListener</code> to be removed
    */
   public void removeFileListener ( PwsFileListener li )
   {
      if ( li != null )
      synchronized ( listeners )   
         { listeners.remove( li ); }
   }
   
   /**
    * Fires a <code>PwsFileEvent</code> of the specified type to the listeners 
    * to this list.
    * @param type event type as defined in <code>PwsFileEvent</code>  
    * @param rec optional record reference
    */
   protected void fireFileEvent ( int type, PwsRecord rec )
   {
      PwsFileEvent evt;
      int i, size;
      
      if ( !eventPause && (size=listeners.size()) > 0 )
      {
         evt = new PwsFileEvent( this, type, rec );
         for ( i = 0; i < size; i++ )
            ((PwsFileListener) listeners.get( i )).fileStateChanged( evt );
      }
   }
   
   /** Sets this list to state MODIFIED and issues a CONTENT_CHANGED event
    * to file listeners.
    * @since 2-1-0
    */ 
   protected void contentModified ()
   {
      setModified();
      fireFileEvent( PwsFileEvent.CONTENT_ALTERED, null );
   }
   
   /**
    * Switch to determine whether file-events shall be dispatched from this
    * record list. (May be used to interrupt event handling during some
    * operation phases.) This value is <b>false</b> by default. 
    * <p>This method issues a LIST_UPDATED event when it switches
    * from state <b>true</b> to state <b>false</b>.
    *  
    * @param v <b>true</b> means events will be dispatched, <b>false</b> they
    *          will not be dispatched 
    * @since 2-0-0
    */
   public void setEventPause ( boolean v )
   {
      boolean old;
      
      old = eventPause;
      eventPause = v;
      if ( old & !eventPause )
      {
         fireFileEvent( PwsFileEvent.LIST_UPDATED, null );
      }
   }
   
   /**
    * Whether this list object is set to not dispatch file events.
    * @return <b>true</b> if and only if this list does not dispatch events
    * @since 2-0-0
    */
   public boolean getEventPause ()
   {
      return eventPause;
   }
   
   /**
    * Assigns a new GROUP value to any set of records within this record list, 
    * replacing previous assignments. Does nothing if the selection is empty.
    * Note on return value: This method doesn't list records as moved whose 
    * group values would not change by the requested operation.
    *  
    * @param set array of <code>DefaultRecordWrapper</code>, may be <b>null</b>
    * @param group a String value for the GROUP record field (may be <b>null</b> 
    *        which is equivalent to empty)
    * @param keepPaths if <b>true</b> previously existing group values will be
    *        appended to the parameter group value  
    * @return <code>DefaultRecordWrapper[]</code> list of records 
    *        actually moved or <b>null</b> if no operation              
    * @since 2-1-0
    */
   public DefaultRecordWrapper[] moveRecords ( DefaultRecordWrapper[] set, 
                                 String group, boolean keepPaths )
   {
      PwsRecordList list, exList;
      PwsRecord rec, setRec;
      String newValue, oldValue;
      int i;
   
      if ( group == null )
         group = "";

      if ( set != null && set.length > 0 )
      {
         // create a list of altered target records  
         list = new PwsRecordList();
         for ( i = 0; i < set.length; i++ )
         {
            setRec = set[i].getRecord();
            if ( (rec = getRecord( setRec.getRecordID() )) != null )
            {
               // expand new group value by old group value (if opted)
               oldValue = rec.getGroup();
               newValue = keepPaths & oldValue != null ? 
                     group.length() > 0 ? group + "." + oldValue : oldValue : group;
               
               // ignore record if its group value doesn't have to be altered
               if ( newValue.equals( oldValue ) )
                  continue;
               
               // set new group value in both update-list AND parameter record set
               rec.setGroup( newValue );
               setRec.setGroup( newValue );
               try { list.addRecord( rec ); }
               catch ( DuplicateEntryException e )
               {}
               catch ( IllegalArgumentException e )
               {}
            }
         }
         
         // modify this list
         if ( (exList = updateRecordList( list )) != null )
            list.removeRecordList( exList );
         
         return list.toRecordWrappers( null );
      }
      return null;
   }  // moveEntries

   /** Merges the parameter record list into this list by optionally respecting 
    *  various conflict handling policies (details see constants of this class). 
    *  Records added by this method receive the transient property "IMPORTED" or 
    *  "IMPORTED_CONFLICT", depending on how they were added. A returned record
    *  list informs the caller about record which have been excluded.
    * 
    * @param list the list of records to be added
    * @param modus the merge conflict solving policy or 0;
    *        policy constants of this class may be combined by OR-ing them
    * @param allowInvalids determines whether invalid records of the source are
    *        excluded (=false) or considered candidates for inclusion (=true)     
    * @return a <code>PwsRecordList</code> holding all <b>not</b> included records
    *         from the parameter list 
    * @since 0-2-0
    */
   public synchronized PwsRecordList merge ( PwsRecordList list, int modus, 
                       boolean allowInvalids )
   {
      PwsRecordList result;
      PwsRecord rec, thisRec;
      Iterator it;
      boolean merge_plain, merge_modified, merge_passmodified,
              merge_passaccessed, merge_expiry;
      boolean fail, oldEvtPause;
      
      // analyse record exclusion options
      merge_plain = modus == MERGE_PLAIN;
      merge_modified = (modus & MERGE_MODIFIED) == MERGE_MODIFIED; 
      merge_expiry = (modus & MERGE_EXPIRY) == MERGE_EXPIRY; 
      merge_passmodified = (modus & MERGE_PASSMODIFIED) == MERGE_PASSMODIFIED; 
      merge_passaccessed = (modus & MERGE_PASSACCESSED) == MERGE_PASSACCESSED; 
      
      // create return record list (failed includes) and activate event pause
      result = new PwsRecordList();
      oldEvtPause = getEventPause();
      setEventPause( true );
      
      for ( it = list.iterator(); it.hasNext(); )
      {
         // get next record from merge source list
         rec = (PwsRecord)it.next();
         
         // exclude record because of its invalid-state (if this filter is opted in parameter)
         if ( !(allowInvalids || rec.isValid()) )
         {
            try { result.addRecord( rec ); }
            catch( Exception e ) 
            {}
            continue;
         }
         
         // branch on containment of record
         if ( this.contains( rec ) )
         
         // if failing because of double entry
         {
            // get this-list record for comparison
            thisRec = getRecordIntern( rec.getRecordID() );
            fail = false;

            try {
               // criteria for record exclusion
               if (  merge_plain ||
                    (merge_modified && rec.getModifiedTime() 
                           <= thisRec.getModifiedTime()) ||
                    (merge_passmodified && rec.getPassModTime() 
                           <= thisRec.getPassModTime()) ||
                    (merge_passaccessed && rec.getAccessTime() 
                           <= thisRec.getAccessTime()) ||
                    (merge_expiry && rec.getPassLifeTime() 
                           <= thisRec.getPassLifeTime())
                  )
               {
                  // exclusion: include excluded record in fail-list
                  fail = true;
                  result.addRecord( rec ); 
               }
               else
               {
                  // inclusion: update included record in this list
                  rec.setImportStatus( PwsRecord.IMPORTED_CONFLICT );
                  this.removeRecord( rec );
                  this.addRecord( rec );
               }
            }
            catch ( Exception e1 )
            {
               System.out.println( "*** Failed Merge Record " 
                    + (fail ? "(exclude-list): " : "(include-list): ")    
                    + rec.toString() + "  " + rec.getTitle() );
               System.out.println( e1 );
            }
            continue;
         }

         // regular include (no-conflict)
         try { 
            rec.setImportStatus( PwsRecord.IMPORTED );
            this.addRecord( rec ); 
         }
         catch ( Exception e )
         {
            try { result.addRecord( rec ); }
            catch ( Exception e1 )
            {          
               System.out.println( "*** Serious Record Failure (merge): " 
                     + rec.toString() + "  " + rec.getTitle() );
               System.out.println( e1 );
            }
         }
      }  // for

      setEventPause( oldEvtPause );
      return result;
   }  // merge
   
   // *******  INNER CLASSES  ************
      
   /**
    * This provides a wrapper around the <code>Iterator</code> that is returned 
    * by the Collections classes.
    * It allows us return record clones only and to mark the list as modified 
    * when records are removed via the iterator.
    */
   private class FileIterator implements Iterator
   {
      private Iterator  iter;
      private PwsRecord record;

      /**
       * Construct the <code>Iterator</code> linking it to the given list.
       * 
       * @param it an <code>Iterator</code> over records
       */
      public FileIterator( Iterator it )
      {
         iter  = it;
      }

      /**
       * Returns <code>true</code> if the iteration has more elements. 
       * 
       * @see java.util.Iterator#hasNext()
       */
      public final boolean hasNext()
      {
         return iter.hasNext();
      }

      /**
       * Returns the next record in the iteration as a clone object.  
       * The object returned will comply to type {@link PwsRecord}
       * 
       * @return the next element in the iteration
       * 
       * @see java.util.Iterator#next()
       */
      public final Object next()
      {
         record = (PwsRecord)iter.next(); 
         return record.clone();
      }

      /**
       * Removes the last returned record from the PasswordSafe
       * file and marks the file as modified.
       * 
       * @see java.util.Iterator#remove()
       */
      public final void remove()
      {
         if ( record != null )
         {
            removeRecord( record );
            setModified();
         }
      }
   }  // class FileIterator 
   
      /**
       * This provides an Iterator over a filtered list of records, namely
       * a selection of records which is determined by a value of the "Group" field. 
       * It allows to mark the file as modified when records are deleted from 
       * the file.
       * 
       * @since 2-0-0 (modified visibilty to private from public) 
       */
      private class GroupFileIterator implements Iterator
      {
         private List grpList;
         private Iterator iter;
         private PwsRecord next;
   
         /**
          * Constructor, filtering the original file's record list
          * and creating a new reference list. If group is the 
          * empty name, this iterator encompasses all list
          * records. If group is <b>null</b> an empty iterator is
          * created.
          * 
          * @param group filter criterion value; may be <b>null</b>
          * @since 0-4-0 (modified parameter list)        
          * @since 2-1-0 (modified parameter logic: group)        
          */
         public GroupFileIterator( String group, boolean exact )
         {
            Iterator it;
            PwsRecord record;
            String grpval;
            int length;
            boolean isAll;
            
            grpList = new ArrayList();
            
            // build the record set of selection criterion
            if ( group != null )
            {
               length = group.length();
               isAll = length == 0;
               for ( it = iterator(); it.hasNext(); )
               {
                  record = (PwsRecord)it.next();
                  if ( isAll )
                     grpList.add( record );
                  else
                  {
                     grpval = record.getGroup();
                     if ( grpval != null && grpval.startsWith( group ) &&
                          ( !exact || grpval.length() == length || 
                          grpval.charAt( length ) == '.' ) )
                        grpList.add( record );
                  }
               }
            }
            
            iter = grpList.iterator();
         }  // constructor
   
         public final boolean hasNext()
         {
            return iter.hasNext();
         }
   
         public final Object next()
         {
            next = (PwsRecord)iter.next();
            return next.clone();
         }
   
         /**
          * Removes the last returned record from the list. 
          */
         public final void remove()
         {
            iter.remove();
            if ( next != null )
               removeRecord( next );
         }
      }  // class GroupFileIterator

   /** Returns the UUID identifier of this record list.
    * @return <code>org.jpws.pwslib.global.UUID</code>
    * @since 2-0-0
    */ 
   public UUID getUUID ()
   {
      return listUUID;
   }

   /** Sets the UUID identifier for this record list. 
    * 
    * @param fileUUID <code>org.jpws.pwslib.global.UUID</code>
    *        (must not be <b>null</b>)
    * @since 2-0-0
    */
   public void setUUID ( UUID fileUUID )
   {
      if ( fileUUID == null )
         throw new NullPointerException();
      
      this.listUUID = fileUUID;
      contentModified();
      Log.log( 7, "(PwsRecordList) set UUID to : " + fileUUID );
   }
   
}
