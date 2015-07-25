/*
 *  RawFieldList in org.jpws.pwslib.data
 *  file: RawFieldList.java
 * 
 *  Project PWSLIB2
 *  @author Wolfgang Keller
 *  Created 27.09.2006
 *  Version
 * 
 *  Copyright (c) 2006 by Wolfgang Keller, Munich, Germany
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

import java.util.HashMap;
import java.util.Iterator;


/** RawFieldList implements a map from field names (0..255) into type {@link PwsRawField}.
 * As field names function the "field types" as the assumption on each rawfield list
 * is that any field type may occur only once.  
 * <p>Fields returned by this list are a deep clone of the listed fields.
 * 
 * @since 2-0-0
 */
public class RawFieldList implements Cloneable
{

/** map of type-ID into rawfields (<code>PwsRawField</code>) */
private HashMap fields;

public RawFieldList ()
{
   fields = new HashMap();
}

/**
 * Creates a raw field list with initial content identical
 * to the parameter raw field list.
 * 
 * @param list source <code>RawFieldList</code>
 * @since 2-1-0
 */
public RawFieldList ( RawFieldList list )
{
   fields = new HashMap( list.fields );
}


/** Returns a shallow copy if this rawfield list.
 *  (Elements of the list are not cloned!)
 */ 
public Object clone ()
{
   RawFieldList o;
   
   try { 
      o = (RawFieldList)super.clone();
      o.fields = (HashMap)this.fields.clone();
      return o;
   }
   catch ( CloneNotSupportedException e )
   { return null; }
}

/** 
  * Returns a field of the given type (=name) from this field list. 
  * (The returned field is a deep copy of the listed field.)  
  *   
  * @param type the requested field type (0..255)
  * @return <code>PwsRawField</code> if the field was found, or 
  *         <b>null</b> otherwise
  */
 public PwsRawField getField ( int type )
 {
    PwsRawField raw;
    Integer key;
    
    key = new Integer( type );
    raw = (PwsRawField)fields.get( key );
    
    return raw == null ? null : (PwsRawField)raw.clone();
 }


/**
  * Sets the content of a field. If the field was already present in this list,
  * the previous content is replaced; otherwise a new field is inserted.
  * 
  * @param field <code>PwsRawField</code> the new field/content
  * @return <code>PwsRawField</code> the previous value of this field if it was 
  *         defined before, <b>null</b> otherwise
  */
 public PwsRawField setField ( PwsRawField field )
 {
    Integer key;
    
    if ( field == null )
       throw new NullPointerException();
    
    key = new Integer( field.type );
    return (PwsRawField) fields.put( key, field );
 }

 /**
  * Removes a field of the given type from this list.
  * Returns the field that was removed or <b>null</b>
  * if no such field was present.
  *  
  * @param type the field id
  * @return <code>PwsRawField</code>
  */
 public PwsRawField removeField ( int type )
 {
    return (PwsRawField)fields.remove( new Integer( type ) );
 }

/**
  * Iterator over all fields of this list (in undefined order).
  * 
  * @return Iterator of element type <code>PwsRawField</code>
  */
 public Iterator iterator ()
 {
    return fields.values().iterator();
 }

 /** 
  * Returns the current number of fields in this list.
  * 
  * @return int list size
  */
public int size ()
{
   return fields.size();
}

/**
 * Returns the size of the data block required to store the content of
 * this field list on a persistent state. (This takes into respect the 
 * general file formating rules of a PWS file.) 
 * 
 * @param format the file format version of the persistent state
 * @return long required (blocked) data space
 * @since 2-0-0
 */
public long blockedDataSize ( int format )
{
   Iterator it;
   long sum;
   
   for ( it = iterator(), sum = 0; it.hasNext(); )
   {
      sum += ((PwsRawField)it.next()).getBlockedSize( format );
   }
   return sum;
}

/**
 * Removes all entries from this list.
 */
public void clear ()
{
   fields.clear();
}

/**
 * Whether this list contains a field of the specified type.
 *  
 * @param type field name
 * @since 2-0-0
 */
public boolean contains ( int type )
{
   return fields.containsKey( new Integer( type ) );
}

/**
 * Returns the total data size of all fields in this list.
 * (The size refers to nominal field lengths, not to required
 * blocked storage space.)
 * 
 * @param format the format version of the persistent state to be considered
 * @return long total data size
 */
public long dataSize ( int format )
{
   Iterator it;
   long sum;
   
   for ( it = iterator(), sum = 0; it.hasNext(); )
      sum += ((PwsRawField)it.next()).getBlockedSize( format );
   return sum;
}

/**
 * Returns a string value interpretation (UTF-8) of a specified element
 * of this list.
 * If field or field value value are missing, an empty string is returned.
 * 
 * @param type field ID
 * @return String field value as text
 */
public String getStringValue ( int type )
{
   PwsRawField raw;
   String value;
   
   value = "";
   if ( (raw = getField( type )) != null )
      value = raw.getString("utf-8");
   return value;
}

}
