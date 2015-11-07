/*
 *  File: HeaderFieldList.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 12.10.2006
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

import java.util.BitSet;
import java.util.Iterator;

import org.jpws.pwslib.global.Global;
import org.jpws.pwslib.global.Log;

/**
 * A descendant of <code>RawFieldList</code> that limits the range of
 * valid elements to field types 0..254 and supplies additional functionality
 * specific to header-field lists. Furthermore, the methods of this class
 * are synchronised.
 * 
 */
public class HeaderFieldList extends RawFieldList
{
   /** The set of header field types canonical to JPWS. */ 
   private static final BitSet VALIDTYPES = new BitSet ();
   static {
      VALIDTYPES.set( 0, PwsFileHeaderV3.LAST_STANDARD_HEADER_FIELD + 1 ); // PWS values 0 .. max standard field
      VALIDTYPES.set( 0xff ); // EOL marker
      VALIDTYPES.set( PwsFileHeaderV3.JPWS_OPTIONS_TYPE );  // JPWS-Options
   }

   /** Creates an empty header field list.
    */
   public HeaderFieldList ()
   {
      super();
   }
   
   /**
    * Creates a header field list with initial content identical
    * to the parameter header field list.
    * 
    * @param list source <code>HeaderFieldList</code>
    */
   public HeaderFieldList ( HeaderFieldList list )
   {
      super( list );
   }
   
   /** Whether the given header-field type is a canonical (=known) field.
    *  ("Canonical" here also includes JPWS defined field types.)
    * 
    * @param type int field type to investigate
    * @return <b>true</b> if and only if the parameter field type is canonical (V3)
    */ 
   public static boolean isCanonicalField ( int type )
   {
      return VALIDTYPES.get( type );
   }


   @Override
   public synchronized PwsRawField setField ( PwsRawField field )
   {
      if ( field.type == 0xff )
         throw new IllegalArgumentException( "illegal field type 0xff" );
      
      return super.setField(field);
   }

   @Override
   public synchronized PwsRawField getField(int type) {
	   return super.getField(type);
   }

   @Override
   public synchronized PwsRawField removeField(int type) {
	   return super.removeField(type);
   }

   
	@Override
	public synchronized Object clone() {
		return super.clone();
	}
	
	@Override
	public synchronized void clear() {
		super.clear();
	}
	
/**
    * Clears away all fields from this list that are not canonical as defined by
    * <code>isCanonicalField()</code> of this class.
    */
   public synchronized void clearUnknownFields ()
   {
      for ( Iterator<PwsRawField> it = super.iterator(); it.hasNext(); ) {
    	 int type = it.next().type;
         if ( !isCanonicalField( type ) ) {
            it.remove();
            Log.debug( 7, "(HeaderFieldList.clearUnknownFields) removed UKF: "
            		.concat(String.valueOf(type)));
         }
      }
   }

	@Override
	public synchronized Iterator<PwsRawField> iterator() {
		return super.iterator();
	}

/**
    * Returns the number of fields which are kept as non-canonical 
    * in this list of header fields.
    * 
    * @return int number of non-canonical fields
    */
   public synchronized int getUnknownFieldCount ()
   {
      int count = 0;
      for ( Iterator<PwsRawField> it = super.iterator(); it.hasNext(); )
         if ( !isCanonicalField( it.next().type ) ) { 
            count++;
         }
      return count;
   }


   /**
    * Returns the total data size of all non-canonical fields  
    * in this list of header fields. (This refers to blocked 
    * data sizes.)
    * 
    * @param format int the file format version of the persistent state
    * @return long size of all non-canonical fields
    */
   public synchronized long getUnknownFieldSize ( int format )
   {
      long sum = 0;
      for ( Iterator<PwsRawField> it = super.iterator(); it.hasNext(); ) {
    	 PwsRawField raw = it.next();
         if ( !isCanonicalField( raw.type ) ) {
            sum += raw.getBlockedSize( format );
         }
      }
      return sum;
   }


   public synchronized long blockedDataSize ( int format )
   {
      // we are adding one block for the EOL marker on file
      return super.dataSize(format) + (format == Global.FILEVERSION_3 ? 16 : 0);
   }
   
}
