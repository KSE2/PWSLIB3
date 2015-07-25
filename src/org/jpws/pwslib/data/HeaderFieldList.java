/*
 *  HeaderFieldList in org.jpws.pwslib.data
 *  file: HeaderFieldList.java
 * 
 *  Project PWSLIB2
 *  @author Wolfgang Keller
 *  Created 12.10.2006
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

import java.util.BitSet;
import java.util.Iterator;

import org.jpws.pwslib.global.Global;
import org.jpws.pwslib.global.Log;

/**
 * A descendant of <code>RawFieldList</code> that limits the range of
 * valid elements to field types 0..254 and supplies additional functionality
 * specific to headerfield lists.
 * 
 * @since 2-0-0
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

   public HeaderFieldList ()
   {
      super();
   }
   
   /**
    * Creates a header field list with initial content identical
    * to teh parameter header field list.
    * 
    * @param list source <code>HeaderFieldList</code>
    * @since 2-1-0
    */
   public HeaderFieldList ( HeaderFieldList list )
   {
      super( list );
   }
   
   /** Whether the given headerfield type is a canonical (=known) field.
    *  ("Canonical" here also includes JPWS defined field types.)
    * 
    * @param type int field type to investigate
    * @return <b>true</b> if and only if the parameter field type is canonical (V3)
    */ 
   public static boolean isCanonicalField ( int type )
   {
      return VALIDTYPES.get( type );
   }


   public PwsRawField setField ( PwsRawField field )
   {
      if ( field.type == 0xff )
         throw new IllegalArgumentException( "illegal field type 0xff" );
      
      return super.setField( field );
   }

   /**
    * Clears away all fields from this list that are not canonical as defined by
    * <code>isCanonicalField()</code> of this class.
    */
   public void clearUnknownFields ()
   {
      PwsRawField raw;
      Iterator it;
      
      for ( it = iterator(); it.hasNext(); )
      {
         raw = (PwsRawField)it.next();
         if ( !isCanonicalField( raw.type ) )
         {
            it.remove();
            Log.debug( 7, "(HeaderFieldList.clearUnknownFields) removed UKF: " + raw.type );
         }
      }

   }


   /**
    * Returns the number of fields which are kept as non-canonical 
    * in this list of header fields.
    * 
    * @return int number of non-canonical fields
    */
   public int getUnknownFieldCount ()
   {
      Iterator it;
      int count;
      
      for ( it = iterator(), count = 0; it.hasNext(); )
         if ( !isCanonicalField( ((PwsRawField)it.next()).type ) ) 
            count++;
      return count;
   }


   /**
    * Returns the total data size of all non-canonical fields  
    * in this list of header fields. (This refers to blocked 
    * data sizes.)
    * 
    * @param format the file format version of the persistent state
    * @return long size of all non-canonical fields
    */
   public long getUnknownFieldSize ( int format )
   {
      PwsRawField raw;
      Iterator it;
      long sum;
      
      for ( it = iterator(), sum = 0; it.hasNext(); )
      {
         raw = (PwsRawField)it.next();
         if ( !isCanonicalField( raw.type ) ) 
            sum += raw.getBlockedSize( format );
      }
      return sum;
   }


   public long blockedDataSize ( int format )
   {
      // we are adding one block for the EOL marker on file
      return super.blockedDataSize( format )
             + (format == Global.FILEVERSION_3 ? 16 : 0);
   }
   
}
