/*
 *  OrderedListEvent in org.jpws.front
 *  file: OrderedListEvent.java
 * 
 *  Project Jpws-Front
 *  @author Wolfgang Keller
 *  Created 28.09.2004
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

import java.util.EventObject;



/**
 *  Event issued for an {@link <code>OrderedListListener</code>}. The event can
 *  be related to a record (wrapper) whose position in a list is described by an 
 *  index value.
 *  @since 0-3-0
 */
public class OrderedListEvent extends EventObject
{
   /** Event type. */
   public static final int ITEM_ADDED = 1;
   /** Event type. */
   public static final int ITEM_REMOVED = 2;
   /** Event type. */
   public static final int LIST_CLEARED = 3;
   /** Event type. Content of list may be totally new. */
   public static final int LIST_RELOADED = 4;

   private DefaultRecordWrapper record;
   private int index;
   private int eventType;
   
/**
 * Creates an event instance.
 */
public OrderedListEvent ( Object source, 
                          int type, 
                          int index, 
                          DefaultRecordWrapper record )
{
   super( source );
   
   if ( type < 1 | type > 4 )
      throw new IllegalArgumentException();
   
   eventType = type;
   this.index = index;
   this.record = record;
}

/** Returns the event type. */
public int getType ()
{
   return eventType;
}

/** Returns the most recent index position of a record if the event type relates 
 *  to a record.
 *  @return list index position
 */
public int getIndex ()
{
   return index;
}

/** Returns the record wrapper of a record if the event type relates to a record.*/
public DefaultRecordWrapper getRecord ()
{
   return record;
}

}
