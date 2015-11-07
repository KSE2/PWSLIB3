/*
 *  File: PwsRecordList.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 07.08.2005
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

import java.nio.charset.IllegalCharsetNameException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.TreeMap;

import org.jpws.pwslib.crypto.SHA256;
import org.jpws.pwslib.exception.DuplicateEntryException;
import org.jpws.pwslib.exception.NoSuchRecordException;
import org.jpws.pwslib.global.Log;
import org.jpws.pwslib.global.UUID;
import org.jpws.pwslib.order.DefaultRecordWrapper;
import org.jpws.pwslib.order.OrderedRecordList;

/**
 *  <b>Identification</b>
 *  <br>Top level structure of this library to represent a list of PWS records
 *  ({@link PwsRecord}). Each instance carries a unique identifier (UUID)
 *  which is supplied automatically but can be set through the interface.
 *  There is a second identifier which is a static instance counter value.
 *  The latter is meant for testing purposes only to discriminate instances
 *  in cases where UUIDs could be identical on various instances. This value
 *  is not operational for any programmatic context; it appears, however, on
 *  several Log messages of this class.  
 *  
 *  <p><b>Containment Logic</b>
 *  <br>The restriction on record entries is that they must be unique in the 
 *  list, measured on their UUID values. The list has a "natural ordering" 
 *  present, which is the ascending order of the UUID values of the elements. 
 *  The reaction to duplicate insertion attempts can be adjusted in subclasses 
 *  by overriding method <code>duplicateInsertion()</code>. The default 
 *  behaviour is to throw a <code>DuplicateEntryException</code>; it can be 
 *  modified to either ignore duplicates or overwrite existing entries. There 
 *  also is a twin class ready which completely ignores duplicates, its name is 
 *  <code>PwsIgDupRecordList</code>.
 *  
 *  <p><b>Some Interface Features</b>
 *  <br>Above plain storage of records and giving a set of records identity,
 *  this class offers additional features. a) operations on the content set 
 *  (merge and set operations, group manipulation), b) mass operating methods,
 *  c) buffered database storage (returned objects are clones of the stored 
 *  objects and stored objects are clones of given objects), d) some 
 *  semantical control of records validity (optional), e) iterator that allows
 *  for concurrent list modification and f) a content signature value. This is 
 *  a memory borne list, hence the total amount of records databases can hold 
 *  may be restricted depending on the user's Java runtime environment.
 *
 *  <p><b>Event Dispatching</b>
 *  <br>This class issues modification events which are defined by class
 *  {@link PwsFileEvent}. Event dispatching occurs synchronous and can be 
 *  suspended and resumed with method <code>setEventPause(boolean)</code>. 
 *  Mass processing methods, like e.g. <code>addCollection()</code>, undertake 
 *  effort to only dispatch a single generic list modification event upon 
 *  termination instead of events for each processed record.
 *  
 *  <p><b>Synchronisation</b>
 *  <br>Note this class is not synchronised. If multiple threads need to modify 
 *  a list instance, they MUST synchronise their activities. 
 *  Adding and removing of file listeners is synchronised.
 *  
 *  <p><b>Terminology</b>
 *  <br>The term "elementary group name" is used in the descriptions. It is
 *  defined as a substring of a GROUP value, starting with index 0 and 
 *  comprising either the total value or ending 1 char before a '.' in the
 *  value.  
 *  
 *  @see PwsFile
 *  @see PwsFileFactory
 *  @see PwsFileListener
 *  @see org.jpws.pwslib.order.OrderedRecordList
 */
public class PwsRecordList implements Cloneable
{
   /** On merge conflict exclude the record.
    */
   public static final int MERGE_PLAIN = 0;
   /** On merge conflict include the record if it is modified younger.
    */
   public static final int MERGE_MODIFIED = 1;
   /** On merge conflict include the record if password is used younger.
    */
   public static final int MERGE_PASSACCESSED = 2;
   /** On merge conflict include the record if password is modified younger.
    */
   public static final int MERGE_PASSMODIFIED = 4;
   /** On merge conflict include the record if password lifetime is longer.
    */
   public static final int MERGE_EXPIRY = 8;
   /** On merge conflict include the record.
    */
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
   
   /** List UUID; always mounted by default, but may also come from an external
    *  state. 
    */
   private UUID  listUUID = new UUID();
   
   /**
    * Map holding the records that are elements of this list, mapping
    * from UUID into PwsRecord.
	*/
   private TreeMap<UUID, PwsRecord> recMap	= new TreeMap<UUID, PwsRecord>();

   /** Event listeners to this list; holds PwsFileListener values.
    * Late instantiation.
    */
   private ArrayList<PwsFileListener> listeners;
   
   /** Counter for list content modifications, including record updates.
    */
   private int modCounter;
   
   private int notedModValue;
   
	/**
	 * Flag indicating whether the file has been modified since creation or
     * last save.
	 */
   protected boolean			modified;
    
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
     * Constructs a new record list with an initial
     * record set as given by the parameter record wrapper array. 
     * Duplicate records in the array lead to an exception thrown.
     * No check for record validity is performed. After initialising the 
     * alteration state of the list is UNMODIFIED.
     * 
     * @param recs <code>DefaultRecordWrapper[]</code> record wrapper objects,
     *        may be <b>null</b>
     * @throws DuplicateEntryException 
     */
    public PwsRecordList( DefaultRecordWrapper[] recs ) 
    		  throws DuplicateEntryException
    {
       initInstance();
       
       if ( recs != null && recs.length > 0 ) {
    	  PwsRecord[] arr = new PwsRecord[ recs.length ];
    	  int i = 0;
	      for ( DefaultRecordWrapper wrp : recs ) {
	    	 arr[i++] = wrp.getRecord(); 
	      }
	      replaceContent(arr);
          resetModified();
       }
    }  // constructor

   /**
     * Constructs a new record list with an initial
     * record set as given by the parameter array. 
     * Duplicate records in the array lead to an exception thrown. No check 
     * for record validity is performed. After initialising the alteration state
     * of the list is UNMODIFIED.
     * 
     * @param recs <code>PwsRecord[]</code> record objects,
     *        may be <b>null</b>
     * @throws DuplicateEntryException 
     */
    public PwsRecordList( PwsRecord[] recs ) throws DuplicateEntryException
    {
        initInstance();

        if ( recs != null ) {
  	      replaceContent(recs);
          resetModified();
        }
    }  // constructor

    /**
     * Constructs a new record list with an initial
     * record set as given by the parameter record collection. 
     * Duplicate records in the array lead to an exception thrown. No check 
     * for record validity is performed. After initialising the alteration state
     * of the list is UNMODIFIED.
     * 
     * @param recs <code>Collection</code> of <code>PwsRecord</code> record list,
     *        may be <b>null</b>
     * @throws DuplicateEntryException 
     */
    public PwsRecordList( Collection<PwsRecord> recs ) 
    		   throws DuplicateEntryException
    {
       this( recs == null ? null : recs.toArray(new PwsRecord[recs.size()]) );
    }  // constructor

   private void initInstance ()
   {
      fileID = instanceCounter++;
      idString = " (" + fileID + "): ";
      Log.log( 2, "(PwsRecList) new PwsRecordList: inst-ID = " + fileID );
   }  // initInstance
   
   /**
    * Returns the record content of this list as an array of (cloned) records.
    * The order of the array corresponds to the natural order of this list. 
    * 
    * @return <code>PwsRecord[]</code>
    */
   public PwsRecord[] toArray ()
   {
      PwsRecord[] arr = new PwsRecord[ size() ];
      Iterator<PwsRecord> it = internalIterator();
      for ( int i = 0; it.hasNext(); i++ ) {
         arr[ i ] = (PwsRecord)it.next().clone();
      }
      return arr;
   }
   
   /**
    * Returns the record content of this list as a <code>List</code> of 
    * (cloned) records. Modifications to the returned list
    * do not strike through to this record list.
    * 
    * @return <code>List</code> of <code>PwsRecord</code>
    */
   public List<PwsRecord> toList () {
	   List<PwsRecord> col = Arrays.asList(toArray());
	   List<PwsRecord> list = new ArrayList<PwsRecord>(col);
	   return list;
   }
   
   /**
    * Returns the content of this list as an array of 
    * <code>DefaultRecordWrapper</code> (of cloned records).
    * 
    * @param locale <code>Locale</code> to be used by wrappers 
    *        or <b>null</b> for system default
    * @return DefaultRecordWrapper[]
    */
   public DefaultRecordWrapper[] toRecordWrappers ( Locale locale )
   {
      return DefaultRecordWrapper.makeWrappers( toArray(), locale );
   }

   /** Method called by this class when an attempt is recognised to insert a
    * duplicate of a record into this list. Records are identified by their
    * UUID value. The default reaction is throwing 
    * a <code>DuplicateEntryException</code>. The user can modify this reaction
    * in a subclass and, where advantageous, add further activity. Other 
    * possible reactions are: returning <b>true</b> means overwrite existing 
    * record, returning <b>false</b> means ignore duplicate.
    * 
    * @param rec <code>PwsRecord</code> duplicate record
    * @return boolean true == overwrite, false == ignore
    * @throws DuplicateEntryException
    */
   protected boolean duplicateInsertion ( PwsRecord rec ) 
		   throws DuplicateEntryException
   {
	   throw new DuplicateEntryException();
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
    * @throws DuplicateEntryException if the record already exists in this list
    * @throws NullPointerException if parameter is <b>null</b>
    */
	public void addRecordValid( PwsRecord rec ) throws DuplicateEntryException
	{
	   if ( !rec.isValid() )
         throw new IllegalArgumentException( "invalid record: " +
               rec.getInvalidText() + " (cannot be added)" );
      
      addRecordIntern( rec, "(addRecordValid)" );
	}

   /**
    * Adds a record to this list by creating a clone of the parameter record. 
    * The condition for adding the record is that its identification (UUID) 
    * may not exist already in this list. This method does not perform any 
    * check on semantical validity of the record.
    * 
    * @param rec <code>PwsRecord</code> the record to be added.
    * @throws DuplicateEntryException if the record already exists
    * @throws NullPointerException if parameter is null
    */
   public void addRecord( PwsRecord rec ) throws DuplicateEntryException
   {
      addRecordIntern( rec, "(addRecord)" );
   }

   /**
    * Adds a clone of the parameter record to this list provided its 
    * identification is not already contained. Upon successful insertion,
    * the internal stored record instance is returned. This method does not 
    * perform any check on semantical validity of the record. 
    * <p>Note that if the record has not been added due to a duplicate 
    * handling setting, <b>null</b> is returned. <u>The return value must not be
    * used to modify the record and not returned to user environment!</u>
    * 
    * @param rec <code>PwsRecord</code> record to be inserted
    * @param report String logging marker
    * @return <code>PwsRecord</code> the internal record object or <b>null</b>
    * @throws DuplicateEntryException if record-ID already exists
    * @throws NullPointerException if rec is null
    */
   protected PwsRecord addRecordIntern( PwsRecord rec, String report )
         throws DuplicateEntryException
   {
      if ( contains(rec) && !duplicateInsertion(rec) ) {
    	 return null; 
      }
   
      PwsRecord copy = (PwsRecord)rec.clone();
      Object replaced = recMap.put( copy.getRecordID(), copy );
      setModified();
      
      if ( Log.getDebugLevel() > 2 )
      Log.debug( 3, "(PwsRecList) record added to list " + report + idString  + rec.toString() 
            + ", entry no. " + (recMap.size()-1) + ", crc=" + rec.getCRC() );
      
      int evType = replaced == null ? PwsFileEvent.RECORD_ADDED :
    	  		   PwsFileEvent.RECORD_UPDATED;
      fireFileEvent( evType, rec );
      return copy;
   }

   
    /** Adds a list of records into this record list. The first occurrence of 
    * a duplicate entry will break execution of insertion and throw an 
    * exception. Does nothing if the parameter is <b>null</b>.
    * <p>Note: this does not check for record validity.
    * 
    * @param list <code>PwsRecordList</code>, may be null
    * @return <code>PwsRecordList</code>, this record list
    * @throws DuplicateEntryException
    */
   public PwsRecordList addRecordList ( PwsRecordList list ) 
		   throws DuplicateEntryException
   {
      if ( list != null && !list.isEmpty() ) {
	      // insert list elements without issuing file-events
	      boolean oldPause = getEventPause();
       	  setEventPause( true );
	      for ( Iterator<PwsRecord> it = list.internalIterator(); it.hasNext(); ) {
	         addRecordIntern( it.next(), "addRecordList" );
	      }
	      setEventPause( oldPause );
      }
      return this;
   }

   /** Adds a collection of records into this record list. The first occurrence 
    * of a duplicate entry will break execution of insertion and throw an 
    * exception. Does nothing if the parameter is <b>null</b>.
    * <p>Note: this does not check for record validity.
    * 
    * @param coll <code>Collection</code> of <code>PwsRecord</code>, may be null
    * @return <code>PwsRecordList</code>, this record list
    * @throws DuplicateEntryException
    */
   public PwsRecordList addCollection (Collection<PwsRecord> coll) 
		   throws DuplicateEntryException 
   {
      if ( coll != null && !coll.isEmpty() ) {
	      // insert list elements without issuing file-events
	      boolean oldPause = getEventPause();
       	  setEventPause( true );
	      for ( Iterator<PwsRecord> it = coll.iterator(); it.hasNext(); ) {
	         addRecordIntern( it.next(), "addCollection" );
	      }
	      setEventPause( oldPause );
      }
      return this;
   }
   
   /** Returns an iterator over the ordered set of elements of this list
    * without inducing the making of clones of the records. This has to be 
    * handled with great care!
    * <p><u>Important Notice</u>: Subclasses of <code>PwsRecordList</code> MUST 
    * not use the direct references supplied by this iterator to modify the 
    * record values or carry them outside of the structure. Otherwise major 
    * features of this class are broken. 
    * 
    * @return Iterator of PwsRecord
    */
   protected Iterator<PwsRecord> internalIterator () 
   {
	   return recMap.values().iterator();
   }
   
   /** Removes a given list of records from this record list and returns a fail
    * list if not all parameter records could be removed. Does nothing if 
    * the parameter is <b>null</b>.
    * 
    * @param list <code>PwsRecordList</code>, may be <b>null</b>
    * @return <code>PwsRecordList</code> of <code>PwsRecord</code>, list of 
    *         records (elements from parameter) which could not be deleted from
    *         this list; <b>null</b> if all elements from the parameter list 
    *         were removed or the parameter was <b>null</b>
    */
   public PwsRecordList removeRecordList ( PwsRecordList list ) 
   {
	  PwsRecordList fList = null;
	  
      if ( list != null && !list.isEmpty() ) {
	      // insert list elements without issuing file-events
	      boolean oldPause = getEventPause();
       	  setEventPause( true );
          for ( Iterator<PwsRecord> it = list.internalIterator(); it.hasNext(); ) {
        	 PwsRecord rec = it.next();
	         PwsRecord delRec = removeRecord( rec.getRecordID() );
	         if ( delRec == null ) {
	        	 if (fList == null) {
	        		 fList = new PwsRecordList();
	        	 }
	        	 try {
					fList.addRecordIntern(rec, "(removeRecordList-fail-entry)");
				} catch (DuplicateEntryException e) {
				}
	         }
	      }
	      setEventPause( oldPause );
      }
      return fList;
   }  // removeRecordList

   /** Removes a collection of records from this record list and returns a fail
    * list if not all parameter records could be removed. Does nothing 
    * if the parameter is <b>null</b>.
    * 
    * @param coll <code>Collection</code> of <code>PwsRecord</code>, may be null
    * @return <code>List</code> of <code>PwsRecord</code>, list of records
    *         (elements from parameter) which could not be deleted from this 
    *         list; <b>null</b> if all elements from the parameter list were 
    *         removed or the parameter was <b>null</b>
    */
   public List<PwsRecord> removeCollection (Collection<PwsRecord> coll) 
   {
	  ArrayList<PwsRecord> fList = null;
	  
      if ( coll != null && !coll.isEmpty() ) {
	      // insert list elements without issuing file-events
	      boolean oldPause = getEventPause();
       	  setEventPause( true );
	      for ( PwsRecord rec : coll ) {
	         PwsRecord delRec = removeRecord( rec.getRecordID() );
	         if ( delRec == null ) {
	        	 if (fList == null) {
	        		 fList = new ArrayList<PwsRecord>();
	        	 }
	        	 fList.add(rec);
	         }
	      }
	      setEventPause( oldPause );
      }
      return fList;
   }
   
   /**
    * Returns a new record list containing the intersection of this record list 
    * with the given record list. If the intersection is empty or the parameter 
    * is <b>null</b>, an empty list is returned. 
    * <p>DEPECATED: This method will be removed in a following release. Use
    * <code>intersectionRecordList()</code> instead!
    * 
    * @param list <code>PwsRecordList</code>, may be null
    * @return <code>PwsRecordList</code> intersection with parameter list
    */
   @Deprecated
   public PwsRecordList cutSetRecordList ( PwsRecordList list )
   {
	   return intersectionRecordList(list);
   }
   
   /**
    * Returns a new record list containing the intersection of this record list 
    * with the given record list. If the intersection is empty or the parameter 
    * is <b>null</b>, an empty list is returned. 
    * 
    * @param list <code>PwsRecordList</code>, may be null
    * @return <code>PwsRecordList</code> intersection with parameter list
    */
   public PwsRecordList intersectionRecordList ( PwsRecordList list )
   {
      PwsRecordList result = new PwsRecordList();
      if ( list != null && !list.isEmpty() ) {
	      for ( Iterator<PwsRecord> it = list.internalIterator(); it.hasNext(); ) {
	    	 PwsRecord rec = it.next(); 
	         if ( contains(rec) ) {
	            try { 
	            	result.addRecordIntern( rec, "(intersection)" );
	            } catch ( DuplicateEntryException e ) {
	            } 
	         }
	      }
      	  result.resetModified();
      }
      return result;
   }
   
   /**
    * Returns a new record list that contains all records of this record list
    * which are not element of the parameter record list. 
    * 
    * @param list <code>PwsRecordList</code>, may be null
    * @return <code>PwsRecordList</code> list without parameter record set
    */
   public PwsRecordList excludeRecordList ( PwsRecordList list )
   {
      PwsRecordList result = copy();
      result.removeRecordList(list);
      result.resetModified();
      return result;
   }
   
   /** Returns a new record list which contains the union set of this record 
    * list with the parameter record list.
    * 
    * @param list <code>PwsRecordList</code>, may be null
    * @return <code>PwsRecordList</code> union set with parameter list
    */
   public PwsRecordList unionRecordList ( PwsRecordList list ) 
   {
      PwsRecordList result = copy();
      if (list != null && !list.isEmpty()) {
	      for (Iterator<PwsRecord> it = list.internalIterator(); it.hasNext(); ) {
	    	  PwsRecord rec = it.next();
	    	  if (!result.contains(rec)) {
				 try { result.addRecordIntern(rec, "union");
				 } catch (DuplicateEntryException e) {
				 }
	    	  }
	      }
		  result.resetModified();
      }
      return result;
   }
   
   /** Updates a list of records in this record list. Unknown 
    *  records of the parameter list are not updated and returned in the
    *  resulting record list. Does nothing if the parameter is <b>null</b>
    *  or the empty list.
    * 
    * @param list <code>PwsRecordList</code> of records to be updated, 
    *        may be <b>null</b>
    * @return <code>PwsRecordList</code> subset of parameter list containing
    *         records which were not updated, <b>null</b> if empty
    */
   public PwsRecordList updateRecordList ( PwsRecordList list ) 
   {
      PwsRecordList result = null;

      if ( list != null && !list.isEmpty() ) {
    	 boolean old = getEventPause();
         setEventPause( true );
         
         // update list elements (without issuing file-events)
         for ( Iterator<PwsRecord> it = list.internalIterator(); it.hasNext(); ) {
        	PwsRecord rec = it.next();
            try { 
            	updateRecord( rec ); 
            } catch ( NoSuchRecordException e ) {
               // insert not matching record to result list	
               // late creation of result list	
               if ( result == null ) {
                  result = new PwsRecordList();
               }
               // insert to result ignoring duplicates
               try { 
            	   result.addRecord( rec ); 
               } catch ( DuplicateEntryException e1 ) {
               }
            }
         }
         setEventPause( old );
      }
      return result;
   }  // updateRecordList

   /** Updates a collection of records in this record list. Unknown 
    *  records of the collection are not updated and returned in the
    *  resulting record list. Does nothing if the parameter is <b>null</b>
    *  or empty.
    *  <p><small>Multiple occurrences of a record in the collection are
    *  permitted, in which case the last occurrence as given by the collection's
    *  iterator is the effective update.</small>
    * 
    * @param coll <code>Collection</code> of <code>PwsRecord</code>, records to 
    *             be updated, may be <b>null</b>
    * @return <code>List</code> of <code>PwsRecord</code>, subset of parameter 
    *         containing records which were not updated, <b>null</b> if 
    *         there are no such records
    */
   public List<PwsRecord> updateCollection ( Collection<PwsRecord> coll ) 
   {
      List<PwsRecord> result = null;

      if ( coll != null && !coll.isEmpty() ) {
    	 boolean old = getEventPause();
         setEventPause( true );
         
         // update list elements (without issuing file-events)
         for ( Iterator<PwsRecord> it = coll.iterator(); it.hasNext(); ) {
        	PwsRecord rec = it.next();
            try { 
            	updateRecord( rec ); 
            } catch ( NoSuchRecordException e ) {
               // insert not matching record to result list	
               // late creation of result list	
               if ( result == null ) {
                  result = new ArrayList<PwsRecord>();
               }
               result.add( rec );
            }
         }
         setEventPause( old );
      }
      return result;
   }  // updateRecordList

   /**
    * Updates an existing record in this list by replacing it with a clone of
    * the parameter record. The record to be updated is
    * identified by its UUID value. 
    * <p><small>Note that changes made to record 
    * objects obtained from this interface will <b>not</b> strike through to the 
    * corresponding list element. Hence the "updateRecord" methods are vital 
    * to change an existing record in the list.</small>
    * 
    * @param rec <code>PwsRecord</code> the record to be updated
    * @throws NoSuchRecordException if the parameter record is unknown
    * @throws NullPointerException if parameter is <b>null</b>
    */
   public void updateRecord ( PwsRecord rec ) throws NoSuchRecordException
   {
      PwsRecord oldRec = getRecordShallow( rec.getRecordID() );
      if ( oldRec == null )
         throw new NoSuchRecordException("failed update on record " + rec);
   
      if ( oldRec.getCRC() != rec.getCRC() ) {
    	 PwsRecord copy = (PwsRecord)rec.clone();
         recMap.put( copy.getRecordID(), copy );
         setModified();
         if ( Log.getDebugLevel() > 2 )
         Log.debug( 3, "(PwsRecordList.updateRecord) record updated in file" + idString  + copy ); 
         fireFileEvent( PwsFileEvent.RECORD_UPDATED, rec );
      }
   }  // updateRecord

   /**
    * Updates an existing valid record in this list. The record to be updated is
    * identified by its UUID value. If the record is not valid an 
    * exception is thrown.
    * 
    * @param rec <code>PwsRecord</code> the record to be updated, must be valid 
    * @throws IllegalArgumentException if the record is not valid
    * @throws NoSuchRecordException if the parameter record is unknown
    * @throws NullPointerException if parameter is <b>null</b>
    */
   public void updateRecordValid( PwsRecord rec ) throws NoSuchRecordException
   {
      if ( !rec.isValid() )
         throw new IllegalArgumentException("invalid record, cannot be updated");
      
      updateRecord( rec );
   }  // updateRecord

   /**
	 * Returns the total number of records in this list.
	 * <p>DEPRECATED: Method may get eliminated in future releases.
	 * Use <code>size()</code> instead!
	 * 
	 * @return int, number of records
	 */
    @Deprecated
	public int getRecordCount()
	{
		return recMap.size();
	}

   /**
	 * Returns the total number of records in this list.
	 * 
	 * @return int, number of records
	 */
	public int size () 
	{
		return recMap.size();
	}
	
   /**
    * Returns an iterator over all records in the natural order of this list. 
    * Records may be deleted from this
    * list by calling the <code>remove()</code> method on the iterator. This 
    * iterator returns records that are clones of the filed 
    * records; records modified by the user have to be "updated" by use of the 
    * <code>updateRecord()</code> method.
    * The iterator allows concurrent modifications of this list.   
    * 
    * @return <code>Iterator</code> of <code>PwsRecord</code>, iterator over 
    *         all records (a snapshot of the list situation at the time point 
    *         of invocation)
    */
   @SuppressWarnings("unchecked")
   public Iterator<PwsRecord> iterator()
   {
      return new FileIterator( ((TreeMap<UUID, PwsRecord>)recMap.clone()).
    		                    values().iterator() );
   }

   /**
    * Returns the total data size of all unknown (non-canonical) fields
    * in this record list. 
    * (This refers to blocked data size according to the specified file format.)
    * 
    * @param format int, the format version of the persistent state to be 
    *               considered
    * @return long unknown data size
    */
   public long getUnknownFieldSize ( int format )
   {
      long sum = 0;
      for ( Iterator<PwsRecord> it = internalIterator(); it.hasNext(); ) {
         sum += it.next().getUnknownFieldSize( format );
      }
      return sum;
   }

   /**
    * Returns the number of data fields which are kept as non-canonical 
    * in this list of records.
    * 
    * @return int, number of non-canonical records
    */
   public int getUnknownFieldCount ()
   {
      int count = 0;
      for ( Iterator<PwsRecord> it = internalIterator(); it.hasNext(); ) {
         count += it.next().getUnknownFieldCount();
      }
      return count;
   }

   /**
    * Clears away all non-canonical fields in this list of records.
    */
   public void clearUnknownFields ()
   {
	  int count = 0;   
      for ( Iterator<PwsRecord> it = internalIterator(); it.hasNext(); ) {
    	 PwsRecord rec = it.next();
    	 int recCount = rec.getUnknownFieldCount();
    	 count += recCount; 
         if ( recCount > 0 ) {
           rec.clearExtraFields();
         }
      }
      if ( count > 0 ) {
         Log.log( 3, "cleared " + count + " unknown fields in reclist " + idString );
         contentModified();
      }
   }

   /**
    * Returns the number of records in this list which belong to the 
    * specified group value, including descendant groups. (Note that
    * this function refers to the same set building principle as 
    * <code>getGroupedRecords()</code>.) 
    * 
    * @param group String GROUP field selection value; may be <b>null</b>
    * @param exact boolean whether elementary group names must match exactly
    *        the parameter
    *  
    * @return int number of grouped records as specified 
    */
   public int getGrpRecordCount( String group, boolean exact )
   {
      if ( group == null ) return 0;
      return new GroupFileIterator(group, exact).grpList.size();
   }

   /**
    * Returns an iterator over all records whose group values matches with the
    * parameter value. Two modi operandi are possible: relaxed and exact. In 
    * exact mode the parameter value must be identical with an <b>elementary 
    * group name</b> in the record group value. In relaxed mode it suffices that
    * the record value starts with the parameter value. Comparison is case 
    * sensitive.
    * <p><u>Example</u>: Parameters <code>"AA.Miriam.Car",true</code> will 
    * return all records belonging to a group with this name, including all 
    * subgroups, but it will not return a record of the "AA.Miriam.Carfesh" 
    * group. In relaxed mode the records of the latter group are also returned. 
    * 
    * <p>If <code>group</code> is the empty name, the returned iterator 
    * encompasses all records without a group value. If group is <b>null</b> 
    * the iterator is empty.
    * 
    * <p>Records may be deleted from this list by calling the <code>remove()
    * </code> method of the iterator.
    * 
    * @param group String GROUP field selection value; may be <b>null</b>
    * @param exact boolean whether elementary group names must match exactly
    *        the parameter
    * @return <code>Iterator</code> of <code>PwsRecord</code>
    */
	public Iterator<PwsRecord> getGroupedRecords ( String group, boolean exact )
    {
      return new GroupFileIterator(group, exact);
    }
	
	/** Returns a record list containing all records belonging to the given
	 * GROUP name. If there is no record for this group name, the empty list
	 * is returned.
	 * 
	 * @param group String selective group name
	 * @return <code>PwsRecordList</code>
	 */
	public PwsRecordList getGroup ( String group ) {
		PwsRecordList list = new PwsRecordList();
		for (Iterator<PwsRecord> it = getGroupedRecords(group, true); it.hasNext();) {
			try { list.addRecord(it.next());
			} catch (DuplicateEntryException e) {
			}
		}
		return list;
	}
   
   /**
    * Returns the number of records which are expired on the date given.
    * 
    * @param date long epoch time-point for this evaluation
    * @return int, number of expired records at <code>date</code>
    */
   public int countExpired ( long date )
   {
      int count = 0;
      for ( Iterator<PwsRecord> it = internalIterator(); it.hasNext(); ) {
         if ( it.next().willExpire( date ) ) {
            count++;
         }
      }
      return count;
   }

   /**
    * Returns the number of invalid records.
    * 
    * @return int number of invalid records
    */
   public int countInvalid ()
   {
      int count = 0;
      for ( Iterator<PwsRecord> it = internalIterator(); it.hasNext(); ) {
         if ( !((PwsRecord)it.next()).isValid() ) {
            count++;
         }
      }
      return count;
   }

   /**
    * Removes all invalid records from this list and returns them
    * as a separate record list.
    * 
    * @return <code>PwsRecordList</code> list of invalid records
    *         or <b>null</b> if no invalid records were inheld
    */
   public PwsRecordList clearInvalidRecs ()
   {
      PwsRecordList list = null;

      // investigate all records for validity
      for ( Iterator<PwsRecord> it = internalIterator(); it.hasNext(); ) {
    	 PwsRecord rec = it.next(); 
         if ( !rec.isValid() ) {
            if ( list == null ) {
               list = new PwsRecordList();
            }
            try { 
               list.addRecordIntern( rec, "(clearInvalidRecs)" );
            } catch ( DuplicateEntryException e ) {
          	}
         }
      }

      // remove invalid records and return list
      if (list != null) {
    	  removeRecordList(list);
      }
      return list;
   }
   
   /**
    * Whether this database has invalid records.
    */
   public boolean hasInvalidRecs ()
   {
      return countInvalid() > 0;
   }
   
   /**
    * Renames the GROUP name of a set of records. The set of records is selected
    * by the parameter <code>group</code> name as if through 
    * <code>getGroupedRecords(group,true)</code>. For each record of the group, 
    * the <b>elementary group name</b> part which is defined by <code>group
    * </code> is replaced by the string <code>newGroup</code>.  
    * 
    * @param group String elementary group name (defines a set of records);
    *        may be <b>null</b> for no operation      
    * @param newGroup String that replaces the <code>group</code> text in the 
    *        records' GROUP field; may be <b>null</b> for ""
    * @return <code>PwsRecordList</code> a list of the records actually modified
    *         by this operation        
    */
   public PwsRecordList renameGroup ( String group, String newGroup )
   {
      PwsRecordList list = new PwsRecordList();
      boolean oldPause = getEventPause();
      setEventPause( true );

      for ( Iterator<PwsRecord> it = getGroupedRecords( group, true ); it.hasNext(); ) {
         PwsRecord rec = it.next();
         String oldGrp = rec.getGroup() == null ? "" : rec.getGroup();
         String newValue = newGroup == null ? "" : newGroup;
         // in case of subgroup, append subgroup text to new group name
         if ( oldGrp.length() > group.length() ) {
            newValue += oldGrp.substring( group.length() );
         }
         rec.setGroup( newValue ); 
         try { 
            updateRecord( rec ); 
            try { 
            	list.addRecordIntern( rec, "* internal rename group *" ); 
            } catch ( Exception e ) {
            }
         } catch ( NoSuchRecordException e ) {
            throw new IllegalStateException( "PWSLIB renameGroup():\r\n" + e );
         }
      }

      setEventPause( oldPause );
      return list;
   }  // renameGroup

   /**
    * Deletes a set of records which is defined by the <code>group</code> 
    * parameter. This affects all records which belong to the specified 
    * <b>elementary group name</b>, including all descendant groups.
    * <p>The set of deleted records is equivalent to <code>
    * getGroupedRecords(group, true)</code>. 
    *   
    * @param group String an elementary group name (of the record GROUP field)
    * @return <code>PwsRecordList</code> with set of records removed
    */
   public PwsRecordList removeGroup ( String group )
   {
	  PwsRecordList result = new PwsRecordList(); 
      boolean oldPause = getEventPause();
      setEventPause( true );
      
      for ( Iterator<PwsRecord> it = getGroupedRecords( group, true ); it.hasNext(); ) {
         try {
			result.addRecord(it.next());
 		 } catch (DuplicateEntryException e) {
		 }
         it.remove();
      }
      setEventPause( oldPause );

      // control success
      if ( containsGroup(group) ) {
    	  throw new IllegalStateException("*** failed to remove GROUP completely: ".concat(group));
      }
      return result;
   }
   
   /** Adds the parameter parent expression to the given list of group names
    * and analyses and adds all predecessor group names of parent.
    * 
    * @param list <code>List</code> of <code>String</code>
    * @param parent String, group name, may be <b>null</b>
    */
   private void addParentGroupNames ( List<String> list, String parent )
   {
      // analyse parent of parent and recurse 
      String pp = PwsRecord.groupParent( parent );
      if ( pp != null ) {
         addParentGroupNames( list, pp );
      }
      
      // try add parent
      if ( !list.contains( parent ) ) {
         list.add( parent );
      }
   }

   /** Returns an ordered list of all <b>elementary group names</b> used in this
    *  record list. Complex group names are analysed into their elementary
    *  group names and all these names included as elements of the list.
    *  Ordering follows collation rules of the actual VM default locale.
    *  The empty group name is considered a possible element. If this 
    *  record list is empty, an empty list is returned.
    *  
    *  @return <code>List</code> of <code>String</code>
    */
   public List<String> getGroupList ()
   {
	   return getGroupList(true);
   }
   
   /** Returns an ordered list of group names used in this
    *  record list. If the parameter is <b>true</b>, complex group names are 
    *  analysed into their elementary group names and all implied names included 
    *  as elements of the list. Otherwise only actually assigned group names
    *  are included.
    *  <p>Ordering follows collation rules of the actual VM default locale.
    *  The empty group name is considered a possible element. If this 
    *  record list is empty, an empty list is returned.
    *
    *  @param analyse boolean true == include implied group names,
    *                         false == only actually assigned group names 
    *  @return <code>List</code> of <code>String</code>
    */
   public List<String> getGroupList (boolean analyse)
   {
      ArrayList<String> list = new ArrayList<String>();
      OrderedRecordList recList = new OrderedRecordList( this );
      recList.loadDatabase( this, 0 );
      String p=null;
      
      for ( int i = 0; i < recList.size(); i++ ) {
         String group = recList.getItemAt( i ).getRecord().getGroup();
         
         // allow empty group as element
         if ( group == null ) {
            group = "";
         }

         // add parent group names
         String parent = PwsRecord.groupParent( group );
         if ( parent != null && !parent.equals(p) ) {
            addParentGroupNames( list, parent );
            p = parent;
         }

         // add group name if not contained
         if ( !list.contains( group ) ) {
            list.add( group );
         }
      }
      
      removeFileListener( recList );
      return list;
   }
   
   /** 
    * Returns the number of distinct and used group names in the file.
    * The empty group name is considered a possible element.
    * 
    * @return int number of distinct groups
    */
   public int getGroupCount ()
   {
      HashMap<String, Object> map = 
    		  new HashMap<String, Object>( Math.max(size(), 32) );
      for ( Iterator<PwsRecord> it = internalIterator(); it.hasNext(); ) {
         String grpval = it.next().getGroup();
         map.put( grpval, null );
      }
      return map.size();
   }
   
   /**
	 * Whether this list or any of its records have been modified.
	 * 
	 * @return <code>true</code> if and only if the content of this list has 
	 *         been modified since the last save or load
	 */
	public boolean isModified ()
	{
		return modified;
	}
	
	/** Whether this record list is empty.
	 * 
	 * @return boolean true == empty list
	 */
	public boolean isEmpty ()
	{
		return size() == 0;
	}

	/**
	 * Deletes the specified record from this list.
     * Does nothing if the parameter is <b>null</b> or the given record is not 
     * contained in this list.
	 * 
	 * @param rec <code>PwsRecord</code> the record to be deleted, may be null
     * @return <code>PwsRecord</code> the record which was removed 
     *         from the list or <b>null</b> if the record was not contained            
	 */
	public PwsRecord removeRecord( PwsRecord rec )
	{
    	if ( rec == null ) return null;
		return removeRecord( rec.getRecordID() );
	}

    /**
    * Deletes the specified record from this list.
    * Does nothing if the parameter is <b>null</b> or the given ID is not 
    * contained in this list. 
    * 
    * @param recID <code>UUID</code> identification of the record to be deleted,
    *        may be <b>null</b>
    * @return <code>PwsRecord</code> the record which was removed 
    *         from the list or null if the record was not contained            
    */
    public PwsRecord removeRecord( UUID recID )
    {
    	if ( recID == null ) return null;

    	PwsRecord deleted = recMap.remove( recID );
		if ( deleted != null ) {
			setModified();
			PwsRecord copy = (PwsRecord)deleted.clone();
			
			if ( Log.getDebugLevel() > 2 )
		    Log.debug( 3, "record removed from list" + idString  + deleted.toString() ); 
            fireFileEvent( PwsFileEvent.RECORD_REMOVED, copy );
            return copy;
		}
		return null;
    }

   /** Whether the specified record is contained in this list.
    * 
    *  @param rec <code>PwsRecord</code> record, may be null
    *  @return <b>true</b> if and only if the parameter is not <b>null</b> 
    *          and a record with the given identification (UUID)  
    *          exists in this list
    */
   public boolean contains ( PwsRecord rec )
   {
      return rec == null ? false : recMap.containsKey( rec.getRecordID() );
   }
   
   /** Whether a record with the specified record-Id (UUID) exists in this list.
    * 
    *  @param recId <code>UUID</code> record Id, may be null
    *  @return <b>true</b> if and only if <code>recId</code> is not <b>null</b>
    *          and a record with the given Id exists in this list
    */
   public boolean contains ( UUID recId )
   {
      return recId == null ? false : recMap.containsKey( recId );
   }

   /** Whether the specified group path exists in this list as a group name.
    * If the parameter is <b>null</b>, <b>false</b> is returned.
    * 
    *  @param group String group name probed, may be <b>null</b>
    *  @return <b>true</b> if and only if there exists at least one record with 
    *          a GROUP value that starts with the parameter group name 
    *          (assuming it to be a complete elemental group name)
    */
   public boolean containsGroup ( String group )
   {
	  if ( group == null ) return false;
	  
      group = PwsRecord.groupNormalized( group );
      int len = group.length();
      for ( Iterator<PwsRecord> it = internalIterator(); it.hasNext(); ) {
         String hstr = it.next().getGroup();
         if ( hstr == null ) hstr = "";
         if ( hstr.startsWith( group ) &&
              (hstr.length() == len || hstr.charAt( len ) == '.') ) {
            return true;
         }
      }
      return false;
   }
   
   /**
    * Returns <b>true</b> if and only if the given record list is not 
    * <b>null</b> and all of its elements are also an element of this list.
    * 
    * @param list <code>PwsRecordList</code>, may be null
    * @return boolean true == parameter list is contained
    */
   public boolean containsRecordList ( PwsRecordList list ) 
   {
	  if ( list == null ) return false;
	  
      for ( Iterator<PwsRecord> it = list.internalIterator(); it.hasNext(); ) {
    	 if ( !contains(it.next()) ) {
    		 return false;
    	 }
      }
      return true;
   }
   
   /**
    * Returns <b>true</b> if and only if the given record collection is not 
    * <b>null</b> and all of its elements are also an element of this list.
    * The empty collection is always contained.
    * 
    * @param coll <code>Collection</code> of <code>PwsRecord</code>, may be null
    * @return boolean true == parameter list is contained
    */
   public boolean containsCollection ( Collection<PwsRecord> coll ) 
   {
	  if ( coll == null ) return false;
	  
      for ( Iterator<PwsRecord> it = coll.iterator(); it.hasNext(); ) {
    	 if ( !contains(it.next()) ) {
    		 return false;
    	 }
      }
      return true;
   }
   
   /**
    * Returns the record with the specified Record-ID as a clone of
    * the stored record of this list.
    * 
    * @param recID <code>UUID</code> Record-ID of the requested record.
    *        may be null
    * @return <code>PwsRecord</code>, the requested record or <b>null</b> if 
    *         such a record is unknown to this list
    */
   public PwsRecord getRecord ( UUID recID )
   {
      PwsRecord rec = getRecordShallow( recID );
      if ( rec != null ) {
         rec = (PwsRecord)rec.clone();
      }
      return rec;
   }
   
   /**
    * Returns a clone of the stored record with Record-ID as given by the 
    * parameter record.
    * 
    * @param rec <code>PwsRecord</code> the requested record, may be null
    * @return <code>PwsRecord</code>, the stored record or <b>null</b> if 
    *         such a record is unknown to this list
    */
   public PwsRecord getRecord ( PwsRecord rec )
   {
      return rec == null ? null : getRecord(rec.getRecordID());
   }
   
   /**
    * Returns the record with the specified Record-ID as a direct reference to
    * the stored record of this list.
    * <p><u>Important Notice</u>: This method MUST 
    * NOT be used to modify the referenced record value or carry it
    * to public. Otherwise major features of this class are broken! 
    * 
    * @param recID <code>UUID</code> Record-ID of the requested record, 
    *              may be null
    * @return <code>PwsRecord</code>, the requested record or <b>null</b> if 
    *         such a record is unknown to this list
    */
   protected PwsRecord getRecordShallow ( UUID recID )
   {
      return recID == null ? null : recMap.get( recID );
   }
   
   /**
    * Returns the size of the data block required to store the content of
    * this record list on a persistent state. (This takes into respect the 
    * general file formating rules of a PWS file of the specified format.) 
    * 
    * @param format int, file format version of the persistent state
    * @param charset String, encoding used for text values 
    * @return long required (blocked) data space
    * @throws IllegalCharsetNameException if charset is unknown to JVM
    */
   public long getBlockedDataSize ( int format, String charset )
   {
      long sum = 0;
      for ( Iterator<PwsRecord> it = internalIterator(); it.hasNext(); ) {
         sum += it.next().getBlockedDataSize( format, charset );
      }
      return sum;
   }

   /**
    * Renders a content signature value for this list of records.
    * Returns a SHA-256 checksum which is a sum-up of all its records' 
    * signatures. Note that this value is not individual for a given list 
    * instance because two lists with identical records (or empty) will have the
    * same signature value.
    * <p>It may not be assumed that this value is identical 
    * over different releases of this software but over different sessions of a
    * program running this package.
    * 
    * @return byte[] 32 byte signature value (SHA-256 digest) 
    */
   public byte[] getSignature ()
   {
      SHA256 sha = new SHA256();
      for ( Iterator<PwsRecord> it = internalIterator(); it.hasNext();  ) {
         sha.update( it.next().getSignature() );
      }
      return sha.digest();
   }
   
	/** Removes all records from this record list.
    */
   public void clear ()
   {
      int size = size();
      if ( size > 0 ) {
         recMap.clear();
         setModified();
         Log.debug( 3, "(PwsRecordList.clear) -- all records removed in list" 
                    + idString  + size );
         fireFileEvent( PwsFileEvent.LIST_CLEARED, null );
      }
   }
   
      /**
    * Returns a shallow clone of this record list (PwsRecordList). 
    * UUID value is the same, File-ID number is modified to be unique and any 
    * registered listeners are removed from the clone. 
    * <p><small>This class treats record values as constants. Neither does it
    * internally modify referenced record instances, nor does it give the user
    * any opportunity to do this. Because of this feature, the shallow clone of
    * this list is functionally equivalent to a deep clone.</small> 
    *      
    * @return <code>Object</code> of type <code>PwsRecordList</code> 
    */
   @Override
   @SuppressWarnings("unchecked")
   public Object clone ()
   {
      PwsRecordList list;

      try { 
    	  list = (PwsRecordList) super.clone(); 
      } catch ( CloneNotSupportedException  e ) { 
    	 return null; 
      }
   
      list.recMap = (TreeMap<UUID, PwsRecord>) recMap.clone();
      list.listeners  = null;
      list.fileID = instanceCounter++;
      list.idString = " (" + list.fileID + "): ";
      Log.log( 2, "(PwsRecList) new PwsRecordList (clone of " + idString + 
               "): inst-ID = " + list.fileID );
      return list;
   }

   /** Returns this list's instance ID value (testing purpose).
    * 
    * @return int instance ID, starting from zero
    */
   public int getInstId () 
   {
	   return fileID;
   }
   
   /**
    * Returns a clone of this record list with a new UUID value. This works
    * the same as <code>clone()</code> but gives the list a new identity and
    * renders the specific type.
    * 
    * @return <code>PwsRecordList</code> 
    */
   public PwsRecordList copy ()
   {
      PwsRecordList list = (PwsRecordList)clone();
      list.setUUID(new UUID());
      list.resetModified();
      
      Log.log( 2, "(PwsRecList) create copy of PwsRecordList " + idString + 
               ": inst-ID = " + list.fileID );
      return list;
   }
   
   /**
    * This method replaces the entire content of this record list, including 
    * its UUID value, with the content of the parameter record list.
    *  Instance ID and file listeners are not replaced!
    *   
    * @param a <code>PwsRecordList</code> new content and identity for this list
    */
   @SuppressWarnings("unchecked")
   public void replaceFrom ( PwsRecordList a )
   {
      listUUID = a.listUUID;
//      listeners = (ArrayList<PwsFileListener>)a.getFileListeners();
      recMap = (TreeMap<UUID, PwsRecord>)a.recMap.clone();
      setModified();
      fireFileEvent( PwsFileEvent.LIST_UPDATED, null );
   }

   /** Replaces the record content of this list with the parameter set of
    * records. If <b>null</b> or the empty array is given, this works
    * equivalent to <code>clear()</code>.
    * <p>Note: This adds clones of the records given by the parameter.
    * 
    * @param recs <code>PwsRecord[]</code>, may be null
    * @throws DuplicateEntryException 
    */
   public void replaceContent ( PwsRecord[] recs ) throws DuplicateEntryException
   {
	   if ( recs == null || recs.length == 0 ) {
		   // same as clear (list-cleared event)
		   clear();
	   } else {
		  // replace content (list-updated event) 
    	  boolean oldPause = getEventPause();
    	  setEventPause(true);
    	  clear();
	      for ( PwsRecord rec : recs ) {
        	 addRecordIntern( rec, "replaceContent" ); 
	      }
	      setEventPause(oldPause);
	   }
   }
   
	/**
	 * Sets the flag to indicate that the list of records has been modified.  
     * (There should not normally be any reason to call this method as it 
     * is called indirectly when a record is added, removed or updated.)
	 */
	protected void setModified()
	{
		modCounter++;
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
    * A specific listener object is listed only once although this method may
    * be called multiple times. Does nothing if the parameter is <b>null</b>.
    * 
    * @param listener <code>PwsFileListener</code>, may be null
    */
   public void addFileListener ( PwsFileListener listener )
   {
      if ( listener != null ) {
    	 if ( listeners == null ) {
    		 listeners = new ArrayList<PwsFileListener>();
    	 }
    	 synchronized ( listeners ) { 
    		if ( !listeners.contains( listener ) ) {
    		   listeners.add( listener );
    		}
    	 }	
      }
   }
   
   /** Returns a copy of the list of file listeners to this record list or
    * <b>null</b> if there are no listeners defined.
    * 
    * <p>Note: Modification to the returned value is harmless.
    * 
    * @return List of <code>PwsFileListener</code> or <b>null</b>
    */
   @SuppressWarnings("unchecked")
   public List<PwsFileListener> getFileListeners ()
   {
	  if ( listeners != null && !listeners.isEmpty() ) { 
	     synchronized ( listeners ) {
	        return (List<PwsFileListener>)listeners.clone();
	     }
	  } 
	  return null;
   }
   
   /**
    * Removes a <code>PwsFileListener</code> from this list of records.
    * 
    * @param listener <code>PwsFileListener</code> to be removed, 
    *                 may be null
    */
   public void removeFileListener ( PwsFileListener listener )
   {
      if ( listeners != null & listener != null )
      synchronized ( listeners ) { 
    	 listeners.remove( listener ); 
      }
   }
   
   /**
    * Fires a <code>PwsFileEvent</code> of the specified type to the listeners 
    * to this list. The operation runs synchronous.
    * 
    * @param type int, event type as defined in class <code>PwsFileEvent</code>  
    * @param rec <code>PwsRecord</code>, optional record reference
    */
   protected void fireFileEvent ( int type, PwsRecord rec )
   {
  	 PwsFileEvent evt = new PwsFileEvent( this, type, rec );
  	 fireFileEvent(evt);
   }
   
   /**
    * Fires the given <code>PwsFileEvent</code> to the listeners 
    * to this list. The operation runs synchronous.
    * 
    * @param event <code>PwsFileEvent</code>, may be null
    */
   protected void fireFileEvent ( PwsFileEvent event )
   {
      if ( event != null && !eventPause && 
    	   listeners != null && !listeners.isEmpty() ) {
         for ( PwsFileListener li : getFileListeners() ) {
            li.fileStateChanged( event );
         }
      }
   }
   
   /** Sets this list to state MODIFIED and issues a CONTENT_ALTERED event
    *  to file listeners.
    */ 
   protected void contentModified ()
   {
      setModified();
      fireFileEvent( PwsFileEvent.CONTENT_ALTERED, null );
   }
   
   /** Returns the UUID identifier of this record list.
    * 
    * @return <code>org.jpws.pwslib.global.UUID</code>
    */ 
   public UUID getUUID ()
   {
      return listUUID;
   }

   /** Sets the UUID identifier for this record list. This replaces the 
    * existing identifier.
    * 
    * @param fileUUID <code>org.jpws.pwslib.global.UUID</code>
    * @throws NullPointerException if parameter is null
    */
   public void setUUID ( UUID fileUUID )
   {
      if ( fileUUID == null )
         throw new NullPointerException();
      
      this.listUUID = fileUUID;
      contentModified();
      Log.log( 7, "(PwsRecordList) set UUID to : " + fileUUID );
   }
   
   /**
    * Switch to determine whether file-events will be dispatched from this
    * record list. This may be used to suppress event firing during some
    * operation phases. The default value is <b>false</b>. 
    * <p>This method issues a LIST_UPDATED event when it switches
    * from state <b>true</b> to state <b>false</b> and the file has been 
    * modified during the events-off phase.
    *  
    * @param value boolean, <b>true</b> means events will be dispatched, 
    *          <b>false</b> they will not be dispatched 
    */
   public void setEventPause ( boolean value )
   {
      boolean old = eventPause;
      eventPause = value;
      boolean risingFlank = !old & eventPause;
      boolean fallingFlank = old & !eventPause;
      if ( risingFlank ) {
    	  notedModValue = modCounter;
      }
      if ( fallingFlank & notedModValue != modCounter ) {
         fireFileEvent( PwsFileEvent.LIST_UPDATED, null );
      }
   }
   
   /**
    * Whether this list object is set to not dispatch file events.
    * 
    * @return boolean <b>true</b> if and only if this list does not dispatch 
    *         events
    */
   public boolean getEventPause ()
   {
      return eventPause;
   }
   
   /**
    * Assigns a new GROUP value to a set of records within this record list 
    * and in the parameter record wrapper array. Modifies only records which
    * are element of this list. Does nothing if the selection is null or empty.
    * 
    * <p>The return value is a new array of wrappers which contains all records
    * actually updated. Note this method doesn't list records whose 
    * group values have not changed by the requested operation.
    *  
    * @param set <code>DefaultRecordWrapper[]</code>, records to update, 
    *        may be <b>null</b>
    * @param group String new value for the GROUP record field (may be 
    *        <b>null</b> which is equivalent to empty)
    * @param keepPaths boolean, if <b>true</b> previously existing group values 
    *        will be appended to the parameter group value  
    * @return <code>DefaultRecordWrapper[]</code> list of records 
    *        actually moved or <b>null</b> if no operation              
    */
   public DefaultRecordWrapper[] moveRecords ( DefaultRecordWrapper[] set, 
                                 String group, boolean keepPaths )
   {
      // no operation if parameter record set is empty
      if ( set == null || set.length == 0 ) return null;

   	  if ( group == null ) {
         group = "";
      }

   	  Locale locale = set.length == 0 ? null : set[0].getLocale();
   	  
     // create a list of altered target records  
   	 ArrayList<PwsRecord> list = new ArrayList<PwsRecord>();
     for ( DefaultRecordWrapper wrapped : set ) {
    	 
    	PwsRecord setRec = wrapped.getRecord();
    	PwsRecord rec = getRecord( setRec.getRecordID() );
        if ( rec != null ) {
           // expand new group value by old group value (if opted)
           String oldValue = rec.getGroup();
           String newValue = keepPaths & oldValue != null ? 
                 group.length() > 0 ? group + "." + oldValue : oldValue : group;
           
           // ignore record if its group value doesn't have to be altered
           if ( newValue.equals( oldValue ) ) {
              continue;
           }
           
           // set new group value in both update-list AND parameter record set
           setRec.setGroup( newValue );
           rec.setGroup( newValue );
       	   list.add( rec ); 
        }
     }

     // return modified records as wrappers or null if nothing modified
     DefaultRecordWrapper[] result = null;
     if ( !list.isEmpty() ) {
	     // modify this list
	     List<PwsRecord> exList = updateCollection( list );
	     if ( exList != null ) {
	        list.removeAll( exList );
	     }
	     
	     // create array of modified records
	     result = DefaultRecordWrapper.makeWrappers( list.toArray(
	    		  new PwsRecord[list.size()]), locale );
     }
     return result;
   }  // moveEntries

   /** Merges the parameter record list into this list by optionally considering 
    *  various conflict handling policies (descriptions see constants of this 
    *  class).
    *  A conflict arises if a record-id is encountered in the parameter list
    *  which is also contained in this list. With the <code>modus</code> 
    *  parameter a set of conflict solving policies can be enabled. If more than
    *  one policy is set up, they are conjuncted with logical AND. That means
    *  if one of the policies indicates exclusion, the record is excluded.
    *  <p>Records added by this method receive the transient property "IMPORTED" or 
    *  "IMPORTED_CONFLICT", depending on how they were added. A returned record
    *  list informs the caller about records which have been excluded. The value
    *  0 is equivalent to MERGE_PLAIN.
    * 
    * @param list <code>PwsRecordList</code> the list of records to be added
    * @param modus int the merge conflict solving policy;
    *        policy constants of this class may be combined by adding them
    * @param allowInvalids boolean determines whether invalid records of the 
    *        source are excluded (=false) or considered candidates (=true)     
    * @return <code>PwsRecordList</code> holding all <b>not</b> included 
    *         records from the parameter list 
    * @throws IllegalArgumentException if modus value is out of range   
    */
   public PwsRecordList merge ( PwsRecordList list, int modus, 
                                boolean allowInvalids )
   {
      PwsRecordList result;
      PwsRecord rec, thisRec;
      boolean merge_plain, merge_modified, merge_passmodified,
              merge_passaccessed, merge_expiry;
      boolean oldEvtPause;
      
      // control parameter
      int bound = MERGE_PLAIN+MERGE_EXPIRY+MERGE_INCLUDE+MERGE_MODIFIED+
    		      MERGE_PASSACCESSED+MERGE_PASSMODIFIED;
      if ( modus < 0 || modus > bound ) 
    	  throw new IllegalArgumentException("illegal modus value: " + modus);
      
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
      
      for ( Iterator<PwsRecord> it = list.internalIterator(); it.hasNext(); ) {
    	  
         // get next record from merge source list
         rec = it.next();
         
         // exclude record because of its invalid-state 
         // if this filter is opted in parameter
         if ( !(allowInvalids || rec.isValid()) ) {
            try { result.addRecord( rec ); 
            } catch( DuplicateEntryException e ) {
            }
            continue;
         }
         
         // branch on containment of record
         // if failing because of double entry
         thisRec = getRecordShallow( rec.getRecordID() );
         if ( thisRec != null ) {
         
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
                  )  {
            	   
                  // exclusion: add excluded record to fail-list
                  result.addRecord( rec ); 

               } else {
                  // inclusion: update included record into this list
                  removeRecord( rec );
                  rec = addRecordIntern( rec, "(merge conflict)" ); 
                  rec.setImportStatus( PwsRecord.IMPORTED_CONFLICT );
               }

            } catch ( DuplicateEntryException e1 ) {
            	e1.printStackTrace();
            }
            continue;
         }

         // regular include (no-conflict)
         try { 
            rec = addRecordIntern( rec, "(merge import)" ); 
            rec.setImportStatus( PwsRecord.IMPORTED );

         } catch ( DuplicateEntryException e ) {
        	 e.printStackTrace();
//            try { result.addRecord( rec ); 
//            } catch ( Exception e1 ) {          
//               System.out.println( "*** Serious Record Failure (merge): " 
//                     + rec.toString() + "  " + rec.getTitle() );
//               System.out.println( e1 );
//            }
         }
      }  // for

      setEventPause( oldEvtPause );
      return result;
   }  // merge
   
   // *******  INNER CLASSES  ************
      
   /**
    * This class provides a wrapper around the <code>Iterator</code> that is 
    * returned by the <code>Collection</code> classes.
    * It enables us to return record clones only via the iterator and mark the 
    * enclosing list as modified when records are removed.
    */
   private class FileIterator implements Iterator<PwsRecord>
   {
      private Iterator<PwsRecord> iter;
      private PwsRecord record;

      /**
       * Creates the <code>FileIterator</code> linking it to the given iterator
       * of records.
       * 
       * @param it <code>Iterator</code> over <code>PwsRecord</code>
       */
      public FileIterator( Iterator<PwsRecord> it ) {
         iter  = it;
      }

      /**
       * Returns <code>true</code> if the iteration has more elements. 
       * 
       * @return boolean 
       * @see java.util.Iterator#hasNext()
       */
      @Override
	  public final boolean hasNext() {
         return iter.hasNext();
      }

      /**
       * Returns the next record in the iteration as a clone object.  
       * The object returned is of type {@link PwsRecord}
       * 
       * @return <code>PwsRecord</code> next element in the iteration
       * @see java.util.Iterator#next()
       */
      @Override
      public final PwsRecord next() {
         record = iter.next(); 
         return (PwsRecord)record.clone();
      }

      /**
       * Removes the last returned record from the enclosing record list
       * and marks the list modified.
       * 
       * @see java.util.Iterator#remove()
       */
      @Override
	  public final void remove() {
         if ( record != null ) {
            removeRecord( record );
         }
      }
   }  // class FileIterator 
   
      /**
       * This class provides an <code>Iterator</code> over a filtered list of 
       * records, based on the enclosing list. The selection of records is 
       * determined by a value of the "GROUP" field. 
       * It allows to mark the file as modified when records are deleted from 
       * the file.
       */
      private class GroupFileIterator implements Iterator<PwsRecord>
      {
         private List<PwsRecord> grpList;
         private Iterator<PwsRecord> iter;
         private PwsRecord next;
   
         /**
          * Constructor filtering the enclosing file's record list
          * and creating a new reference list. If group is <b>null</b> an 
          * empty iterator is created.
          * 
          * @param group String filter value for GROUP field, may be <b>null</b>
          */
         public GroupFileIterator( String group, boolean exact )
         {
            grpList = new ArrayList<PwsRecord>();
            
            // build the record set of selection criterion
            if ( group != null ) {
               int length = group.length();
               boolean isEmpty = length == 0;
               for ( Iterator<PwsRecord> it = internalIterator(); it.hasNext(); ) {
                  PwsRecord record = it.next();
                  String grpval = record.getGroup();
                  if ( isEmpty && grpval == null ||
                	  grpval != null && grpval.startsWith( group ) &&
                      ( !exact || grpval.length() == length || 
                      grpval.charAt( length ) == '.' ) ) {
                	 
                     grpList.add( (PwsRecord)record.clone() );
                  }
               }
            }
            
            iter = grpList.iterator();
         }  // constructor
   
         @Override
         public final boolean hasNext() {
            return iter.hasNext();
         }
   
         @Override
		 public final PwsRecord next() {
            next = iter.next();
            return next;
         }
   
         /**
          * Removes the last returned record from the enclosing list. 
          */
         @Override
		 public final void remove() {
            iter.remove();
            if ( next != null ) {
               removeRecord( next );
            }
         }
      }  // class GroupFileIterator

}
