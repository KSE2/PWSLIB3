/*
 *  file: PwsFileEvent.java
 * 
 *  Project JPasswords
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

package org.jpws.pwslib.data;

import java.util.EventObject;

/**
 *  Events available for <code>PwsFileListener</code> objects.
 *  <p>RECORD_ADDED  when a record is added to the list
 *  <br>RECORD_REMOVED  when a record is removeded from the list
 *  <br>RECORD_UPDATED  when an existing record in the list has been updated
 *  <br>LIST_CLEARED  when the list was cleared (all records removed)
 *  <br>LIST_UPDATED  when the list content was modified in a multi-record or unknown way
 *  <br>LIST_SAVED  when the list has been saved to a persistent state (all records)
 *  <br>TARGET_ALTERED  when the persistency target definition of a file has been
 *                   changed
 *  <br>PASSPHRASE_ALTERED  when the passphrase definition of a file has been
 *                   changed
 *  <br>CONTENT_ALTERED  when some content of the file has been altered that is not
 *              covered by one of the other event types (e.g. file option string)
 */
public class PwsFileEvent extends EventObject
{
   public static final int RECORD_ADDED = 1;
   public static final int RECORD_REMOVED = 2;
   public static final int RECORD_UPDATED = 3;
   public static final int LIST_CLEARED = 4;
   public static final int LIST_UPDATED = 9;
   public static final int LIST_SAVED = 7;
   public static final int TARGET_ALTERED = 5;
   public static final int PASSPHRASE_ALTERED = 6;
   public static final int CONTENT_ALTERED = 8;
   
   private PwsRecord record;
   private int eventType;
   
   
/** Constructor.
 * 
 * @param source the event issuing object
 * @param type the event type as defined by this class
 * @param ref a <code>PwsRecord</code> that will be obtainable through the
 *        <code>getRecord()</code> method; may be <b>null</b>
 */
public PwsFileEvent ( Object source, int type, PwsRecord ref )
{
   super( source );

   if ( type < 1 | type > 9 )
      throw new IllegalArgumentException("illegal event type");
   
   eventType = type;
   record = ref;
}  // constructor

/** The record involved in the event or <b>null</b> if unavailable. 
 *  By convention the returned record is a clone of the corresponding
 *  record in the list. */ 
public PwsRecord getRecord ()
{
   return record;
}

/** The event type. */ 
public int getType ()
{
   return eventType;
}
}
