/*
 *  OrderedRecordList in org.jpws.front
 *  file: OrderedRecordList.java
 * 
 *  Project Jpws-Front
 *  @author Wolfgang Keller
 *  Created 27.09.2004
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

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Locale;

import javax.swing.ListModel;

import org.jpws.pwslib.data.PwsFile;
import org.jpws.pwslib.data.PwsFileEvent;
import org.jpws.pwslib.data.PwsFileListener;
import org.jpws.pwslib.data.PwsRecord;
import org.jpws.pwslib.data.PwsRecordList;

/**
 *  Represents an ordered list of <code>DefaultRecordWrapper</code> objects
 *  which may (or may not) belong to a specific, singular <code>PwsRecordList
 *  </code>.
 *  List altering actions, like insertion and removal of records or loading
 *  of a database, preserve the order of the list. Record-wrappers may be 
 *  addressed by their index numbers in the list.
 * 
 *  <p>The design of this class is to function as a "middleware" between a 
 *  record database object and any record aware data model which needs reference
 *  to a sorted order of its items. The <code>OrderedRecordList</code> hereby 
 *  listens to modification events of the underlying database
 *  and transforms them into events of the sorted list. This class may, however, 
 *  also be used for simpler (or likewise more complex) purposes of sorting 
 *  records as the bondage to a database is not mandatory. 
 *  
 *  <p>The sorting follows a fixed combination of values, namely GROUP + TITLE.
 *  Sorting follows the <code>Collator</code> class to guarantee locale 
 *  sensitive sorting success.
 *  
 *  <p>This class issues events for <code>OrderedListListener</code>s to reflect
 *  any list modifications. At the same time this class is a 
 *  <code>PwsFileListener</code>  and - if records were loaded from a Pws record
 *  list - it listens to modifications of this database and aligns the elements 
 *  of this list accordingly. This design allows to update even complex display 
 *  component arrangements by simply modifying the underlying record database. 
 * 
 */
public class OrderedRecordList implements PwsFileListener
{
   /** The PWS record database to which this ordered list is related. */ 
   protected PwsRecordList boundDbf;
   
   /** The PWS record database to which this ordered list is related. */ 
   protected PwsRecordList loadedDbf;
   
   /** The <code>java.util.List</code> holding <code>DefaultRecordWrapper</code>
    * objects representing the content of <code>loadedDbf</code> in sorted order.
    */ 
   protected ArrayList<DefaultRecordWrapper> list = new ArrayList<DefaultRecordWrapper>();
   
   private Locale locale = Locale.getDefault();
   private ArrayList<OrderedListListener> listeners = new ArrayList<OrderedListListener>();
   private long expireScope;

   
/** Constructor for an ordered record list without database bondage
 *  for the current default locale.
 */ 
public OrderedRecordList ()
{
}  // constructor
   
/** Constructor for an ordered record list without database bondage
 *  for the specified locale.
 * 
 *  @param locale activated locale for sorting 
 */ 
public OrderedRecordList ( Locale locale )
{
   if ( locale != null )
      this.locale = locale;
}  // constructor
   
/** Constructor for an ordered record list which is related to a 
 *  <code>PwsRecordList</code> object. The current VM default locale
 *  is used for sorting records. 
 *  <p><b>Note:</b> In order to load data from and listen to the record list
 *  the method <code>loadDatabase()</code> must be called once. The constructor
 *  however determines database bondage of this object.
 * 
 * @param f the <code>PwsRecordList</code> to which the records 
 *        of this odered list must belong 
 */
public OrderedRecordList ( PwsRecordList f )
{
   if ( f == null )
      throw new IllegalArgumentException();
   
   boundDbf = f;
}  // constructor

/** Constructor for an ordered record list which is related to a 
 *  <code>PwsRecordList</code> object and which is sorted after the specified
 *  locale.
 *  <p><b>Note:</b> In order to load data from and listen to a record list
 *  the method <code>loadDatabase()</code> must be called once. The constructor
 *  however determines database bondage of this object.
 * 
 * @param f the <code>PwsRecordList</code> to which the records 
 *        of this odered list must belong 
 * @param locale activated locale for sorting 
 */
public OrderedRecordList ( PwsRecordList f, Locale locale )
{
   if ( f == null )
      throw new IllegalArgumentException();
   
   boundDbf = f;
   if ( locale != null ) {
      this.locale = locale;
   }
}  // constructor

/** Tests if the parameter record complys with database bondage of this list.
 *  In case of non-compliance an exception is thrown.
 * 
 *  @param rec record to be evaluated
 *  @throws IllegalArgumentException ("unrelated record") if bondage violation
 */
protected void verifyBondage ( PwsRecord rec )
{
   if ( boundDbf != null && !boundDbf.contains( rec ) )
      throw new IllegalArgumentException( "unrelated record" );
}

/** Inserts an element into this list. If this list is bound to a
 *  <code>PwsRecordList</code> object, the record must be an element of it. 
 *  <p>WARNING!! Applying this when this list has bondage may lead to 
 *  de-synchronization of list and database. This method does not insert a 
 *  record into the database!
 * 
 *  @param record DefaultRecordWrapper record to be inserted
 *  @throws IllegalArgumentException if the record fails to conform
 */
public void insertItem ( DefaultRecordWrapper record )
{
   DefaultRecordWrapper wrap = record;
   verifyBondage( wrap.getRecord() );
   insertRecordIntern( wrap );
   fireOrderedListEvent( OrderedListEvent.ITEM_ADDED, wrap.getIndex(), wrap );
}

/** Inserts a record representation into the sorted list without verifying 
 *  file bondage and without issuing <code>OrderedListEvent</code>.
 * 
 *  @param wrap record representation object
 */  
protected void insertRecordIntern ( DefaultRecordWrapper wrap )
{
   int index = list.size();
   for ( int i = 0; i < list.size(); i++ ) {
	  DefaultRecordWrapper item = (DefaultRecordWrapper) list.get( i );
      if ( wrap.compareTo( item ) < 0 ) {
         index = i;
         break;
      }
   }
   list.add( index, wrap );
   wrap.setIndex( index );
}

/** Loads a list of <code>PwsRecord</code>s from a <code>PwsRecordList</code> 
 *  object by discarding any previous content. If this object is bound to a 
 *  <code>PwsFile</code>, the parameter <code>list</code> must also be a
 *  <code>PwsFile</code> and have an identical resource file (persistent file). 
 *  If this object is not bound to a database, this method does, however, 
 *  <u>not</u> lead to bondage, regardless of the instance type of 
 *  <code>list</code>.
 *  <p>This method makes this object listen to the parameter record list for
 *  content change events.
 * 
 *  @param rlist database to be loaded
 *  @param expireScope time span in milliseconds for expire-soon status of 
 *         records; 0 for ignore
 * 
 *  @throws IllegalArgumentException if the parameter does not fit the bound dbf
 */   
public void loadDatabase ( PwsRecordList rlist, long expireScope )
{
   if ( boundDbf != null && boundDbf instanceof PwsFile && 
        !((PwsFile)boundDbf).equalResource( (PwsFile)rlist ) )
      throw new IllegalArgumentException( "unrelated database: " + 
            ((PwsFile)rlist).getFilePath() );
   
   loadedDbf = rlist;
   this.expireScope = expireScope;
   rlist.addFileListener( this );
   clearIntern();
   for ( Iterator<PwsRecord> it = rlist.iterator(); it.hasNext(); ) {
	  DefaultRecordWrapper wrap = makeRecordWrapper( it.next(), locale );
      insertRecordIntern( wrap ); 
   }
   // issue either LIST_CLEARED or LIST_RELOADED depending on resulting list size
   int evt = size() == 0 ? OrderedListEvent.LIST_CLEARED : OrderedListEvent.LIST_RELOADED;
   fireOrderedListEvent( evt, -1, null );
}

/**
 * Reloads (resorts) the content of the record list (which was last loaded
 * by use of <code>loadDatabase()</code>. This is an expensive operation 
 * and will cause a LIST_RELOADED event. Does nothing if there was no list
 * loaded.
 */
public void reload ()
{
   if ( loadedDbf != null ) {
      loadDatabase( loadedDbf, expireScope );
   }
}

/** The default function used by this class to create wrappers for records. 
 *  May be overridden by
 *  user applications to supply a specific record wrapper type (which must be a
 *  subclass of <code>DefaultRecordWrapper</code>).
 * 
 * @param rec PwsRecord
 * @param locale Locale
 * @return <code>DefaultRecordWrapper</code> containing the argument record
 */
public DefaultRecordWrapper makeRecordWrapper ( PwsRecord rec, Locale locale )
{
   DefaultRecordWrapper wrap = new DefaultRecordWrapper( rec, locale );
   if ( expireScope >= 0 ) {
      wrap.refreshExpiry( expireScope );
   }
   return wrap;
}

/** The number of elements in this list.
 */
public int size ()
{
   return list.size();
}

/** Returns an element record (wrapper) of this list from its sequence index.
 * 
 * @param index int
 * @return <code>DefaultRecordWrapper</code> if <code>index</code> is in
 *         defined range, or <b>null</b> otherwise
 */
public DefaultRecordWrapper getItemAt ( int index )
{
   return index > -1 && index < list.size() ? list.get( index ) : null;
}

/**
 * Returns the set of records that belong to the specified GROUP value.
 * (returns original listed wrapper objects.)
 *  
 * @param group selective group value; if <b>null</b> an empty array is returned
 * @param exact whether select value must be a complete existing group name
 * @return array of <code>DefaultRecordWrapper</code>
 */
public DefaultRecordWrapper[] getGroup ( String group, boolean exact )
{
   ArrayList<DefaultRecordWrapper> outlist;
   DefaultRecordWrapper rec;
   String grpval;
   int i, length;

   if ( group == null ) {
      return new DefaultRecordWrapper[ 0 ];
   }
   
   outlist = new ArrayList<DefaultRecordWrapper>();
   length = group.length();
   for ( i = 0; i < list.size(); i++ ) {
      rec = list.get( i );
      grpval = rec.getGroup();
      if ( grpval.startsWith( group ) &&
           ( !exact || length == 0 || 
             grpval.length() == length || grpval.charAt( length ) == '.' ) )  {

    	  outlist.add( rec );
      }
   }
   return outlist.toArray( new DefaultRecordWrapper[outlist.size()] );
}  // getGroup

/** Returns the active locale used to collate sortvalues of this list.
 */ 
public final Locale getLocale ()
{
   return locale;
}

/** Returns the index position of the parameter record in this list.
 * 
 *  @param rec the <code>PwsRecord</code> to be searched
 *  @return index position or -1 of the record is unknown
 */ 
public int indexOf ( PwsRecord rec )
{
   return rec == null ? -1 : list.indexOf( makeRecordWrapper( rec, locale ));
}

/** Returns the index position of the parameter record in this list.
 * 
 *  @param rec the record to be searched, represented by 
 *         <code>DefaultRecordWrapper</code>
 *  @return index position or -1 of the record is unknown
 */ 
public int indexOf ( DefaultRecordWrapper rec )
{
   return rec == null ? -1 : list.indexOf( rec );
}

/** Removes the element at a specified index position from this list.
 *  Does nothing if index is out of range.
 *  <p>WARNING!! Applying this method when this list has bondage may lead to 
 *  de-synchronization of list and database. This method does not remove a 
 *  record from the database.
 */
public void removeItem ( int index )
{
   if ( index > -1 && index < list.size() ) {
	  DefaultRecordWrapper item = (DefaultRecordWrapper)list.get( index );
      list.remove( index );
      fireOrderedListEvent( OrderedListEvent.ITEM_REMOVED, index, item );
   }
}

/** Removes all elements from this list. */
public void clear ()
{
   if ( size() > 0 ) {
      clearIntern();
      fireOrderedListEvent( OrderedListEvent.LIST_CLEARED, -1, null );
   }
}

/** Removes all elements from this list without issuing a list event. */
protected void clearIntern ()
{
   list.clear();
}

/** Sets the time scope for which level EXPIRE_SOON of wrapper records EXPIRY 
 *  status is set. This method recalculates the status of all records; the start
 *  time of the scope is the actual system time.
 * 
 *  @param time time period in milliseconds
 */
public void setExpireScope ( long time )
{
   if ( size() > 0 ) {
      for ( Iterator<DefaultRecordWrapper> it = list.iterator(); it.hasNext(); ) {
         it.next().refreshExpiry( time );
      }
      fireOrderedListEvent( OrderedListEvent.LIST_RELOADED, -1, null );
   }
}

/** Adds a listener to the <code>OrderedListEvent</code>s that this list
 *  is issuing.
 *  
 * @param lis <code>OrderedListListener</code> object
 */ 
public void addOrderedListListener ( OrderedListListener lis )
{
	synchronized (listeners ) {
		listeners.add( lis );
	}
}

/** Removes the given <code>OrderedListListener</code> from this list.
 * 
 * @param listener <code>OrderedListListener</code>
 */
public void removeOrderedListListener ( OrderedListListener listener )
{
	synchronized (listeners ) {
		listeners.remove( listener );
	}
}

@SuppressWarnings("unchecked")
protected ArrayList<OrderedListListener> getListeners () {
	synchronized (listeners ) {
		return (ArrayList<OrderedListListener>)listeners.clone();
	}
}

protected void fireOrderedListEvent ( int type, int index, DefaultRecordWrapper rec )
{
   OrderedListEvent event = new OrderedListEvent( this, type, index, rec );
   ArrayList<OrderedListListener> copy = getListeners();
   for ( int i = 0; i < copy.size(); i++ ) {
      copy.get( i ).orderedListPerformed( event );
   }
}

/** Test function printing the content of the ordered list in the sorted
 *  order. (The resulting line per record is index-nr, sort-value and 
 *  record-id.)
 * 
 * @param out <code>PrintStream</code>
 */ 
public void printout ( PrintStream out )
{
   out.println();
   String hstr = "- record list -";
   if ( boundDbf != null && boundDbf instanceof PwsFile ) {
      hstr = ((PwsFile)boundDbf).getFilePath();
   }
   out.println( "+++ ORDERLIST PRINTOUT for DB : " + hstr );
   
   for ( int i = 0; i < size(); i++ ) {
	  DefaultRecordWrapper item = (DefaultRecordWrapper) list.get( i );
      PwsRecord rec = item.getRecord();
      out.println( "   - rec (" + i + ") " + item.getSortValue() + ", " +
            rec.getRecordID() );
   }
   out.println( "#" );
}

// ********* IMPLEMENTATION OF PwsFileListener **********

   /** Implementation the <code>PwsFileListener</code> interface for this class. 
    */
   @Override
   public void fileStateChanged ( PwsFileEvent evt )
   {
      int type = evt.getType();
      PwsRecord record = evt.getRecord();
      
      if ( type == PwsFileEvent.RECORD_ADDED ) {
         insertItem( makeRecordWrapper( record, locale ) );
      }
      
      else if ( type == PwsFileEvent.RECORD_REMOVED ) {
         int i = indexOf( record );
         if ( i > -1 && i < size() )
            removeItem( i );
      }
      
      else if ( type == PwsFileEvent.RECORD_UPDATED ) {
         int i = indexOf( record );
         if ( i > -1 && i < size() ) {
            removeItem( i );
            insertItem( makeRecordWrapper( record, locale ) );
         }
      }
      
      else if ( type == PwsFileEvent.LIST_UPDATED ) {
         reload();
      }
      
      else if ( type == PwsFileEvent.LIST_CLEARED ) {
         clear();
      }
   }
}
