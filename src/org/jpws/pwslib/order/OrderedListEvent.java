/*
 *  File: OrderedListEvent.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 28.09.2004
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

import java.util.EventObject;


/**
 *  Event issued for an {@link <code>OrderedListListener</code>}. The event can
 *  be related to a record (wrapper) whose position in a list is described by an 
 *  index value.
 */
public class OrderedListEvent extends EventObject
{
   /** Event type. */
   public static final int ITEM_ADDED = 1;
   /** Event type. */
   public static final int ITEM_REMOVED = 2;
   /** Event type. */
   public static final int ITEM_UPDATED = 3;
   /** Event type. */
   public static final int LIST_CLEARED = 4;
   /** Event type. Content of list may be totally new. */
   public static final int LIST_RELOADED = 5;

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
   
   if ( type < 1 | type > 5 )
      throw new IllegalArgumentException();
   
   eventType = type;
   this.index = index;
   this.record = record;
}

/** Returns the event type.
 * 
 *  @return int
 */
public int getType ()
{
   return eventType;
}

/** Returns the most recent list index position of a record if the event 
 * type relates to a record.
 *  
 *  @return int, index position or -1
 */
public int getIndex ()
{
   return index;
}

/** Returns the wrapper of a record if the event type relates to a record.
 * 
 * @return <code>DefaultRecordWrapper</code> or <b>null</b>
 */
public DefaultRecordWrapper getRecord ()
{
   return record;
}

}
