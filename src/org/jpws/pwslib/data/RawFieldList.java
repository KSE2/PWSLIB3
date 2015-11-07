/*
 *  File: RawFieldList.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 27.09.2006
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

import java.util.Iterator;
import java.util.TreeMap;


/** RawFieldList implements a sorted map from field names (0..255) into type 
 * {@link PwsRawField}. Field names function as the "field types" as the 
 * assumption on each rawfield list is that any field type may occur only once.  
 * <p>Fields returned by this list are a deep clone of the listed fields.
 * 
 */
public class RawFieldList implements Cloneable
{

/** Map of type-ID (Integer) into raw-fields (<code>PwsRawField</code>) */
private TreeMap<Integer, PwsRawField> fields = new TreeMap<Integer, PwsRawField>();

public RawFieldList () {
}

/**
 * Creates a raw field list with initial content identical
 * to the parameter raw field list.
 * 
 * @param list source <code>RawFieldList</code>
 */
public RawFieldList ( RawFieldList list ) 
{
   fields = new TreeMap<Integer, PwsRawField>( list.fields );
}


/** Returns a shallow copy if this rawfield list.
 *  (Elements of the list are not cloned!)
 */ 
@Override
@SuppressWarnings("unchecked")
public Object clone ()
{
   try { 
	  RawFieldList list = (RawFieldList)super.clone();
      list.fields = (TreeMap<Integer, PwsRawField>)this.fields.clone();
      return list;
   } catch (CloneNotSupportedException e) { 
	  return null; 
   }
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
    Integer key = new Integer( type );
    PwsRawField raw = (PwsRawField)fields.get( key );
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
    if ( field == null )
       throw new NullPointerException();
    
    Integer key = new Integer( field.type );
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
    return (PwsRawField)fields.remove( type );
 }

/**
  * Iterator over all fields of this list (in ascending sorted order).
  * 
  * @return Iterator of element type <code>PwsRawField</code>
  */
 public Iterator<PwsRawField> iterator ()
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
 * @param format int the file format version of the persistent state
 * @return long required (blocked) data space
 */
public long dataSize ( int format )
{
   long sum = 0;
   for ( Iterator<PwsRawField> it = iterator(); it.hasNext(); ) {
      sum += it.next().getBlockedSize( format );
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
 * @param type int field name
 */
public boolean contains ( int type )
{
   return fields.containsKey( type );
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
   String value = "";
   PwsRawField raw = getField( type );
   if ( raw != null ) {
      value = raw.getString("utf-8");
   }
   return value;
}

}
