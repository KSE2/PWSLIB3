/*
 *  FilterRecordList in org.jpws.data
 *  file: FilterRecordList.java
 * 
 *  Project Jpws-Front
 *  @author Wolfgang Keller
 *  Created 30.08.2005
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

import org.jpws.pwslib.data.PwsFileEvent;
import org.jpws.pwslib.data.PwsRecordList;

/**
 *  This is an abstract class for a filter class that resides above an
 *  <code>OrderedRecordList</code> L. The filter class is an <code>
 *  OrderedListListener</code> and performs the selection of a subset of
 *  the items contained in L. The filter class performs widely as an <code>
 *  OrderedRecordList</code> itself and thus is capable of substituting the
 *  role of <code>OrderedRecordList</code> for its listeners. It is, however,
 *  notably not a <code>PwsFileListener</code> (although it formally say so)!
 *  <p>The filtering function is performed over a callback function <code>
 *  acceptEntry(PwsRecord)</code>. This method is to be implemented by a concrete
 *  filter class.  
 *  @since 0-3-0
 */
public abstract class FilterRecordList extends OrderedRecordList 
                              implements OrderedListListener
{
   private OrderedRecordList orderList;
   
/**
 *  Constructor.
 * 
 * @param list ordered list that is the data reference base for this instance
 */
public FilterRecordList ( OrderedRecordList list )
{
   super( list.getLocale() );
   orderList = list;
   ;
   orderList.addOrderedListListener( this );
}


/** This method is not supported in this class. The formal interface <code>
 *  PwsFileListener</code> is not operative in this class. */
public void fileStateChanged ( PwsFileEvent evt )
{
   throw new UnsupportedOperationException("disabled parent function in this class");
}

public void loadDatabase ( PwsRecordList list, long expireScope )
{
   orderList.loadDatabase( list, expireScope );
}

/** Inserts an element into this list. If this list is bound to a
 *  <code>PwsRecordList</code> object, the record must be an element of it. 
 *  <p>WARNING!! Applying this when this list has bondage may lead to 
 *  de-synchronization of list and database. This method does not insert a 
 *  record into the database.
 * 
 *  @param wrapper <code>DefaultRecordWrapper</code> of record to be inserted
 *  @throws IllegalArgumentException if the record fails to conform
 */
public void insertItem ( DefaultRecordWrapper wrapper )
{
   orderList.clearBondage( wrapper.getRecord() );
   insertRecordIntern( wrapper );
   fireOrderedListEvent( OrderedListEvent.ITEM_ADDED, wrapper.getIndex(), wrapper );
}

/** Resorts the items contained in this list. (This will issue a LIST_RELOADED
 *  event.) 
 */
public void refresh ()
{
   orderedListPerformed( new OrderedListEvent( this, OrderedListEvent.LIST_RELOADED,
         0, null ));
}

public void setExpireScope ( long time )
{
   orderList.setExpireScope( time );
}

/** Performs the filtering criterion for this list based on a <code>PwsRecord</code>
 *  value.
 * 
 *  @param rec a entry candidate for this list
 *  @return <b>true</b> if this candidate has to be included into this list 
 */
public abstract boolean acceptEntry ( DefaultRecordWrapper rec );

//  ***********  IMPLEMENTATION OF OrderedListListener  ***************

public void orderedListPerformed ( OrderedListEvent evt )
{
   DefaultRecordWrapper wrap;
   int eventType, index, i;
   
   eventType = evt.getType();
   wrap = evt.getRecord();
   
   if ( eventType == OrderedListEvent.LIST_RELOADED )
   {
      list.clear();
      for ( i = 0; i < orderList.size(); i++ )
      {
         wrap = orderList.getItemAt( i );
         if ( acceptEntry( wrap ) )
            insertRecordIntern( wrap );
      }
      fireOrderedListEvent( OrderedListEvent.LIST_RELOADED, -1, null );
   }
   
   else if ( eventType == OrderedListEvent.LIST_CLEARED )
   {
      clear();
   }
   
   else if ( eventType == OrderedListEvent.ITEM_REMOVED )
   {
      if ( (index = indexOf( wrap )) > -1 )
         removeItem( index );
   }
   
   else if ( eventType == OrderedListEvent.ITEM_ADDED )
   {
      if ( acceptEntry( wrap ) )
         insertItem( wrap );
   }
   
}
   
}
