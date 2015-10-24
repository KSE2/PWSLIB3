/*
 *  TestC_InputSocket in org.jpws.pwslib.data
 *  file: TestC_InputSocket.java
 * 
 *  Project PWSLIB2
 *  @author Wolfgang Keller
 *  Created 27.08.2006
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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import junit.framework.TestCase;

import org.jpws.pwslib.exception.UnsupportedFileVersionException;
import org.jpws.pwslib.exception.WrongFileVersionException;
import org.jpws.pwslib.global.Global;
import org.jpws.pwslib.global.Util;

/**
 *  
 * @since 2-0-0
 */
public class TestC_InputSocket  extends TestCase
{

   public TestC_InputSocket ()
   {
      super();
   }

   public TestC_InputSocket ( String name )
   {
      super( name );
   }

public InputStream getPwsInputStream( int version, PwsPassphrase key )
{
   return getPwsInputStream( version, key, 0 );
}

public PwsRecordList getPwsRecordList ( int dataCode )
{
   PwsRecordList list;
   PwsRecord rec;
   
   list = new PwsRecordList();
   
   try {
      // create data records if opted
      switch ( dataCode )
      {
      case 1:
      case 2:
         //
         rec = new PwsRecord();
         rec.setTitle( "Hans Hase" );
         rec.setPassword( new PwsPassphrase( "abc" ) );
         rec.setUsername( "Hasimaus" );
         rec.setNotes( "Zugang zum Tresor, muﬂ man sich verschaffen!" );
         list.addRecord( rec );
         break;
      }
   }
   catch ( Exception e )
   {
      fail( "Exception during creation of record list: " + e );
   }
   
   return list;
}

public InputStream getPwsInputStream( int version, PwsPassphrase key, PwsRecordList list )
{
   PwsRecord rec;
   ByteArrayOutputStream out;
   byte[] data;
   
   // construct
   out = new ByteArrayOutputStream();
   try {
      PwsFileFactory.saveFile( list.iterator(), out, key, null, 0, version );
      
   }
   catch ( IOException e )
   {
      throw new IllegalStateException( "IOException: " + e );
   }
   
   // return resulting data block
   data = out.toByteArray();
   return new ByteArrayInputStream( data ); 
}

public InputStream getPwsInputStream( int version, PwsPassphrase key, int dataCode )
{
   return getPwsInputStream( version, key, getPwsRecordList( dataCode) );
}

public void test_construct ()
{
   PwsFileInputSocket si;
   PwsPassphrase key;
   InputStream input;
   

   // test null parameter
   try { 
      new PwsFileInputSocket( null );
      fail( "socket init failure: missing exception on null stream" );
   }
   catch ( Exception e )
   {
      assertTrue( "socket init failure: wrong exception type on null stream", 
            e instanceof NullPointerException );
   }
   
   // test correct creation
   key = new PwsPassphrase( "abc" );
   input = getPwsInputStream( Global.FILEVERSION_2, key );
   si = new  PwsFileInputSocket( input );
   
   assertFalse( "closed socket, open state is false", si.isOpen() );
   assertTrue( "closed socket, no file version", si.getFileVersion() == 0 );

   // IllegalStateException when socket is closed  
   try { 
      si.getBlockInputStream();
      fail( "closed socket get blockstream failure: missing exception" );
   }
   catch ( Exception e )
   {
      assertTrue( "closed socket get blockstream failure: wrong exception", 
            e instanceof IllegalStateException );
   }
   
   try { 
      si.getRawFieldReader();
      fail( "closed socket get rawfieldreader failure: missing exception" );
   }
   catch ( Exception e )
   {
      assertTrue( "closed socket get rawfieldreader failure: wrong exception", 
            e instanceof IllegalStateException );
   }
}

public void test_OpenAttempt ()
{
   PwsFileInputSocket si;
   PwsPassphrase key;
   InputStream input;
   boolean ok;
   int dataCode, count;

   
   // test correct creation
   key = new PwsPassphrase( "abc" );
   
   try {
      // *** VERSION 2 TESTING ***
      count = 0;
      while ( count++ < 2 )
      {
         dataCode = count == 1 ? 0 : 1;
         
         // generic open on V2 file
         input = getPwsInputStream( Global.FILEVERSION_2, key, dataCode );
         si = new  PwsFileInputSocket( input );
   
         ok = si.attemptOpen( new PwsPassphrase() );
         assertFalse( "socket open fails on wrong password, 1", ok );
         
         ok = si.attemptOpen( new PwsPassphrase( "Hound of Baskerville" ) );
         assertFalse( "socket open fails on wrong password, 1a", ok );
         
         ok = si.attemptOpen( new PwsPassphrase( "abc" ) );
         assertTrue( "socket open succeeds on good password, 1", ok );
         
         assertTrue( "socket open, open state, 1", si.isOpen() );
         assertTrue( "socket open, correct file version, 1", si.getFileVersion() == Global.FILEVERSION_2 );
         
         // specific V2-open on V2 file
         input = getPwsInputStream( Global.FILEVERSION_2, key, dataCode );
         si = new  PwsFileInputSocket( input );
   
         ok = si.attemptOpen( new PwsPassphrase(), Global.FILEVERSION_2 );
         assertFalse( "socket open fails on wrong password, 2", ok );
         
         ok = si.attemptOpen( new PwsPassphrase( "abc" ), Global.FILEVERSION_2 );
         assertTrue( "socket open succeeds on good password, 2", ok );
         
         assertTrue( "socket open, open state, 2", si.isOpen() );
         assertTrue( "socket open, correct file version, 2", si.getFileVersion() == Global.FILEVERSION_2 );
         
         // specific V3-open on V2 file
         input = getPwsInputStream( Global.FILEVERSION_2, key, dataCode );
         si = new  PwsFileInputSocket( input );
   
         try {
            ok = si.attemptOpen( new PwsPassphrase(), Global.FILEVERSION_3 );
            fail( "socket open fails V3 on V2, 1" );
         }
         catch ( Exception e )
         {
            assertTrue( "socket open fails V3 on V2, Exception type", 
                  e instanceof UnsupportedFileVersionException );
         }
         
         try {
            ok = si.attemptOpen( new PwsPassphrase( "abc" ), Global.FILEVERSION_3 );
            fail( "socket open fails V3 on V2, wrong version" );
         }
         catch ( Exception e )
         {
            assertTrue( "socket open fails V3 on V2, wrong version, Exception type", 
                  e instanceof UnsupportedFileVersionException );
         }

         assertFalse( "socket open, open state, 3", si.isOpen() );
         assertTrue( "socket open, zero file version, 3", si.getFileVersion() == 0 );
         
         // specific V1-open on V2 file
         input = getPwsInputStream( Global.FILEVERSION_2, key, dataCode );
         si = new  PwsFileInputSocket( input );
   
         ok = si.attemptOpen( new PwsPassphrase(), Global.FILEVERSION_1 );
         assertFalse( "socket open fails on wrong password, 4", ok );
         
         try {   
            ok = si.attemptOpen( new PwsPassphrase( "abc" ), Global.FILEVERSION_1 );
            fail( "socket open fails on wrong file version, 4" );
         }
         catch ( Exception e )
         {
            assertTrue( "socket open fails on wrong file version, exception type: ", 
                  e instanceof WrongFileVersionException );
         }
         
         assertFalse( "socket open, open state, 4", si.isOpen() );
         assertTrue( "socket open, zero file version, 4", si.getFileVersion() == 0 );
         
         // still must be able to open on good V2 settings
         ok = si.attemptOpen( new PwsPassphrase( "abc" ), Global.FILEVERSION_2 );
         assertTrue( "socket open succeeds after previous failed version matches, V2", ok );
      }
      
      // *** VERSION 1 TESTING ***
      count = 0;
      while ( count++ < 2 )
      {
         dataCode = count == 1 ? 0 : 1;
         
         // generic open on V1 file
         input = getPwsInputStream( Global.FILEVERSION_1, key, dataCode );
         si = new  PwsFileInputSocket( input );
   
         ok = si.attemptOpen( new PwsPassphrase() );
         assertFalse( "socket open fails on wrong password, 1", ok );
         
         ok = si.attemptOpen( new PwsPassphrase( "Hound of Baskerville" ) );
         assertFalse( "socket open fails on wrong password, 1a", ok );
         
         ok = si.attemptOpen( new PwsPassphrase( "abc" ) );
         assertTrue( "socket open succeeds on good password, 1", ok );
         
         assertTrue( "socket open, open state, 1", si.isOpen() );
         assertTrue( "socket open, correct file version, 1", si.getFileVersion() == Global.FILEVERSION_1 );
         
         // specific V1-open on V1 file
         input = getPwsInputStream( Global.FILEVERSION_1, key, dataCode );
         si = new  PwsFileInputSocket( input );
   
         ok = si.attemptOpen( new PwsPassphrase(), Global.FILEVERSION_1 );
         assertFalse( "socket open fails on wrong password, 2", ok );
         
         ok = si.attemptOpen( new PwsPassphrase( "abc" ), Global.FILEVERSION_1 );
         assertTrue( "socket open succeeds on good password, 2", ok );
         
         assertTrue( "socket open, open state, 2", si.isOpen() );
         assertTrue( "socket open, correct file version, 2", si.getFileVersion() == Global.FILEVERSION_1 );
         
         // specific V3-open on V1 file
         input = getPwsInputStream( Global.FILEVERSION_1, key, dataCode );
         si = new  PwsFileInputSocket( input );
   
         try {   
            ok = si.attemptOpen( new PwsPassphrase(), Global.FILEVERSION_3 );
            fail( "socket open fails V3 on V1, 1" );
         }
         catch ( Exception e )
         {
            assertTrue( "socket open fails V3 on V1, Exception type", 
                  e instanceof UnsupportedFileVersionException );
         }
         
         try {   
            ok = si.attemptOpen( new PwsPassphrase( "abc" ), Global.FILEVERSION_3 );
            fail( "socket open fails V3 on V1, wrong version" );
         }
         catch ( Exception e )
         {
            assertTrue( "socket open fails V3 on V1, wrong version, Exception type", 
                  e instanceof UnsupportedFileVersionException );
         }
         
         assertFalse( "socket open, open state, 3", si.isOpen() );
         assertTrue( "socket open, zero file version, 3", si.getFileVersion() == 0 );

         // still must be able to open on good V1 settings
         ok = si.attemptOpen( new PwsPassphrase( "abc" ), Global.FILEVERSION_1 );
         assertTrue( "socket open succeeds after previous failed version matches, V1", ok );
         assertTrue( "socket open, correct file version, 3", si.getFileVersion() == Global.FILEVERSION_1 );

      }
      
      // specific V2-open on V1 file
      input = getPwsInputStream( Global.FILEVERSION_1, key, 1 );
      si = new  PwsFileInputSocket( input );

      ok = si.attemptOpen( new PwsPassphrase(), Global.FILEVERSION_2 );
      assertFalse( "socket open fails on wrong password, 4", ok );
      
      try {   
         ok = si.attemptOpen( new PwsPassphrase( "abc" ), Global.FILEVERSION_2 );
         fail( "socket open fails on wrong file version, 4" );
      }
      catch ( Exception e )
      {
         assertTrue( "socket open fails on wrong file version, exception type: ", 
               e instanceof WrongFileVersionException );
      }
      
      assertFalse( "socket open, open state, 4", si.isOpen() );
      assertTrue( "socket open, zero file version, 4", si.getFileVersion() == 0 );
      
      // still must be able to open on good V1 settings
      ok = si.attemptOpen( new PwsPassphrase( "abc" ), Global.FILEVERSION_1 );
      assertTrue( "socket open succeeds after previous failed version matches, V1", ok );
      assertTrue( "socket open, correct file version, 4", si.getFileVersion() == Global.FILEVERSION_1 );

      
      // *** VERSION 3 TESTING ***
      count = 0;
      while ( count++ < 2 )
      {
         dataCode = count == 1 ? 0 : 1;
         
         // generic open on V3 file
         input = getPwsInputStream( Global.FILEVERSION_3, key, dataCode );
         si = new  PwsFileInputSocket( input );
   
         ok = si.attemptOpen( new PwsPassphrase() );
         assertFalse( "V3, socket open fails on wrong password, 1", ok );
         
         ok = si.attemptOpen( new PwsPassphrase( "Hound of Baskerville" ) );
         assertFalse( "V3, socket open fails on wrong password, 1a", ok );
         
         ok = si.attemptOpen( new PwsPassphrase( "abc" ) );
         assertTrue( "V3, socket open succeeds on good password, 1", ok );
         
         assertTrue( "V3, socket open, open state, 1", si.isOpen() );
         assertTrue( "V3, socket open, correct file version, 1", si.getFileVersion() == Global.FILEVERSION_3 );
         
         // specific V3-open on V3 file
         input = getPwsInputStream( Global.FILEVERSION_3, key, dataCode );
         si = new  PwsFileInputSocket( input );
   
         ok = si.attemptOpen( new PwsPassphrase(), Global.FILEVERSION_3 );
         assertFalse( "V3, socket open fails on wrong password, 2", ok );
         
         ok = si.attemptOpen( new PwsPassphrase( "abc" ), Global.FILEVERSION_3 );
         assertTrue( "V3, socket open succeeds on good password, 2", ok );
         
         assertTrue( "V3, socket open, open state, 2", si.isOpen() );
         assertTrue( "V3, socket open, correct file version, 2", si.getFileVersion() == Global.FILEVERSION_3 );
         
         // specific V2-open on V3 file
         input = getPwsInputStream( Global.FILEVERSION_3, key, dataCode );
         si = new  PwsFileInputSocket( input );
   
         ok = si.attemptOpen( new PwsPassphrase(), Global.FILEVERSION_2 );
         assertFalse( "V3, socket open fails V2 on V3, bad password", ok );
         
         ok = si.attemptOpen( new PwsPassphrase( "abc" ), Global.FILEVERSION_2 );
         assertFalse( "V3, socket open fails V2 on V3, good password", ok );
         
         assertFalse( "V3, socket open, open state, 3", si.isOpen() );
         assertTrue( "V3, socket open, zero file version, 3", si.getFileVersion() == 0 );

         // still must be able to open on good V3 settings
         ok = si.attemptOpen( new PwsPassphrase( "abc" ), Global.FILEVERSION_3 );
         assertTrue( "V3, socket open succeeds after previous failed version matches", ok );
         assertTrue( "V3, socket open, correct file version", si.getFileVersion() == Global.FILEVERSION_3 );

      }
      
      
      // specific V1-open on V3 file
/*      
      input = getPwsInputStream( Global.FILEVERSION_1, key, 1 );
      si = new  PwsFileInputSocket( input );

      ok = si.attemptOpen( new PwsPassphrase(), Global.FILEVERSION_2 );
      assertFalse( "socket open fails on wrong password, 4", ok );
      
      try {   
         ok = si.attemptOpen( new PwsPassphrase( "abc" ), Global.FILEVERSION_2 );
         fail( "socket open fails on wrong file version, 4" );
      }
      catch ( Exception e )
      {
         assertTrue( "socket open fails on wrong file version, exception type: ", 
               e instanceof WrongFileVersionException );
      }
      
      assertFalse( "socket open, open state, 4", si.isOpen() );
      assertTrue( "socket open, zero file version, 4", si.getFileVersion() == 0 );
      
      // still must be able to open on good V1 settings
      ok = si.attemptOpen( new PwsPassphrase( "abc" ), Global.FILEVERSION_1 );
      assertTrue( "socket open succeeds after previous failed version matches, V1", ok );
      assertTrue( "socket open, correct file version, 4", si.getFileVersion() == Global.FILEVERSION_1 );
*/
   }
   catch ( IOException e )
   {
      fail( "IOException: " + e );
   }
   catch ( WrongFileVersionException e )
   {
      fail( "WrongFileVersionException" );
   }
   catch ( UnsupportedFileVersionException e )
   {
      fail( "UnsupportedFileVersionException" );
   }
}

public void test_operate_blocks_V2 ()
{
   PwsFileInputSocket si;
   PwsPassphrase key;
   InputStream input;
   PwsBlockInputStream stream;
   byte[] block;
   boolean ok;
   
   key = new PwsPassphrase( "abc" );
   System.out.println( "---- TEST OPERATION BLOCKSTREAM ON V2 FILE" ); 
   
   try {
      input = getPwsInputStream( Global.FILEVERSION_2, key, 1 );
      si = new  PwsFileInputSocket( input );

      ok = si.attemptOpen( key );
      assertTrue( "socket open, 1", ok );

      stream = si.getBlockInputStream();

      // failure of secondary stream call
      try { 
         si.getBlockInputStream();
         fail( "secondary get blockstream failure: missing exception" );
      }
      catch ( Exception e )
      {
         assertTrue( "secondary get blockstream failure: wrong exception", 
               e instanceof IllegalStateException );
      }
      
      // failure of secondary reader call
      try { 
         si.getRawFieldReader();
         fail( "secondary get rawfieldreader failure: missing exception" );
      }
      catch ( Exception e )
      {
         assertTrue( "secondary get rawfieldreader failure: wrong exception", 
               e instanceof IllegalStateException );
      }
      
      // dump blockstream content
      while ( stream.isAvailable() )
      {
         block = stream.readBlock();
         assertTrue( "block input stream, block length control", block.length == stream.getBlockSize() );
         
         System.out.println( stream.getCount() + " :  " + Util.bytesToHex( block ) );
      }
      System.out.println();
   }
   catch ( Exception e )
   {
	  e.printStackTrace(); 
      fail( "IOException: " + e );
   }
}

public void test_operate_blocks_V3 ()
{
   PwsFileInputSocket si;
   PwsPassphrase key;
   InputStream input;
   PwsBlockInputStream stream;
   byte[] block;
   boolean ok;
   
   key = new PwsPassphrase( "abc" );
   System.out.println( "---- TEST OPERATION BLOCKSTREAM ON V3 FILE" ); 
   
   try {
      input = getPwsInputStream( Global.FILEVERSION_3, key, 1 );
      si = new  PwsFileInputSocket( input );

      ok = si.attemptOpen( key );
      assertTrue( "socket open, 1", ok );

      stream = si.getBlockInputStream();

      // failure of secondary stream call
      try { 
         si.getBlockInputStream();
         fail( "secondary get blockstream failure: missing exception" );
      }
      catch ( Exception e )
      {
         assertTrue( "secondary get blockstream failure: wrong exception", 
               e instanceof IllegalStateException );
      }
      
      // failure of secondary reader call
      try { 
         si.getRawFieldReader();
         fail( "secondary get rawfieldreader failure: missing exception" );
      }
      catch ( Exception e )
      {
         assertTrue( "secondary get rawfieldreader failure: wrong exception", 
               e instanceof IllegalStateException );
      }
      
      // dump blockstream content
      while ( stream.isAvailable() )
      {
         block = stream.readBlock();
         assertTrue( "block input stream, block length control", block.length == stream.getBlockSize() );
         
         System.out.println( stream.getCount() + " :  " + Util.bytesToHex( block ) );
      }
      System.out.println();
   }
   catch ( Exception e )
   {
      fail( "IOException: " + e );
   }
}

public void test_operate_rawfields_V2 ()
{
   PwsFileInputSocket si;
   PwsPassphrase key;
   InputStream input;
   PwsRawFieldReader reader;
   PwsRawField raw;
   boolean ok;
   
   key = new PwsPassphrase( "abc" );
   System.out.println( "---- TEST OPERATION RAWFIELDS ON V2 FILE" ); 
   
   try {
      input = getPwsInputStream( Global.FILEVERSION_2, key, 1 );
      si = new  PwsFileInputSocket( input );

      ok = si.attemptOpen( key );
      assertTrue( "socket open, 1", ok );

      reader = si.getRawFieldReader();

      // failure of secondary stream call
      try { 
         si.getBlockInputStream();
         fail( "secondary get blockstream failure: missing exception" );
      }
      catch ( Exception e )
      {
         assertTrue( "secondary get blockstream failure: wrong exception", 
               e instanceof IllegalStateException );
      }
      
      // failure of secondary reader call
      try { 
         si.getRawFieldReader();
         fail( "secondary get rawfieldreader failure: missing exception" );
      }
      catch ( Exception e )
      {
         assertTrue( "secondary get rawfieldreader failure: wrong exception", 
               e instanceof IllegalStateException );
      }
      
      // dump blockstream content
      while ( reader.hasNext() )
      {
         raw = (PwsRawField)reader.next();
         System.out.println( "Rawfield: T=" + raw.type + ", L=" + raw.length + ", data=" + 
               Util.bytesToHex( raw.data ) );
         
//         System.out.println( );
      }
      System.out.println();
   }
   catch ( Exception e )
   {
      fail( "IOException: " + e );
   }
}

public void test_operate_rawfields_V3 ()
{
   PwsFileInputSocket si;
   PwsPassphrase key;
   InputStream input;
   PwsRawFieldReader reader;
   PwsRawField raw;
   boolean ok;
   
   key = new PwsPassphrase( "abc" );
   System.out.println( "---- TEST OPERATION RAWFIELDS ON V3 FILE" ); 
   
   try {
      input = getPwsInputStream( Global.FILEVERSION_2, key, 1 );
      si = new  PwsFileInputSocket( input );

      ok = si.attemptOpen( key );
      assertTrue( "socket open, 1", ok );

      reader = si.getRawFieldReader();

      // failure of secondary stream call
      try { 
         si.getBlockInputStream();
         fail( "secondary get blockstream failure: missing exception" );
      }
      catch ( Exception e )
      {
         assertTrue( "secondary get blockstream failure: wrong exception", 
               e instanceof IllegalStateException );
      }
      
      // failure of secondary reader call
      try { 
         si.getRawFieldReader();
         fail( "secondary get rawfieldreader failure: missing exception" );
      }
      catch ( Exception e )
      {
         assertTrue( "secondary get rawfieldreader failure: wrong exception", 
               e instanceof IllegalStateException );
      }
      
      // dump blockstream content
      while ( reader.hasNext() )
      {
         raw = (PwsRawField)reader.next();
         System.out.println( "Rawfield: T=" + raw.type + ", L=" + raw.length + ", data=" + 
               Util.bytesToHex( raw.data ) );
         
//         System.out.println( );
      }
      System.out.println();
   }
   catch ( Exception e )
   {
      fail( "IOException: " + e );
   }
}

public void test_operate_blocks_V1 ()
{
   PwsFileInputSocket si;
   PwsPassphrase key;
   InputStream input;
   PwsBlockInputStream stream;
   byte[] block;
   boolean ok;
   
   key = new PwsPassphrase( "abc" );
   System.out.println( "---- TEST OPERATION BLOCKSTREAM ON V1 FILE" ); 
   
   try {
      input = getPwsInputStream( Global.FILEVERSION_1, key, 1 );
      si = new  PwsFileInputSocket( input );

      ok = si.attemptOpen( key );
      assertTrue( "socket open, 1", ok );

      stream = si.getBlockInputStream();

      // failure of secondary stream call
      try { 
         si.getBlockInputStream();
         fail( "secondary get blockstream failure: missing exception" );
      }
      catch ( Exception e )
      {
         assertTrue( "secondary get blockstream failure: wrong exception", 
               e instanceof IllegalStateException );
      }
      
      // failure of secondary reader call
      try { 
         si.getRawFieldReader();
         fail( "secondary get rawfieldreader failure: missing exception" );
      }
      catch ( Exception e )
      {
         assertTrue( "secondary get rawfieldreader failure: wrong exception", 
               e instanceof IllegalStateException );
      }
      
      // dump blockstream content
      while ( stream.isAvailable() )
      {
         block = stream.readBlock();
         assertTrue( "block input stream, block length control", block.length == stream.getBlockSize() );
         
         System.out.println( stream.getCount() + " :  " + Util.bytesToHex( block ) );
      }
      System.out.println();
   }
   catch ( Exception e )
   {
	  e.printStackTrace(); 
      fail( "IOException: " + e );
   }
}

public void test_operate_rawfields_V1 ()
{
   PwsFileInputSocket si;
   PwsPassphrase key;
   InputStream input;
   PwsRawFieldReader reader;
   PwsRawField raw;
   byte[] block;
   boolean ok;
   
   key = new PwsPassphrase( "abc" );
   System.out.println( "---- TEST OPERATION RAWFIELDS ON V1 FILE" ); 
   
   try {
      input = getPwsInputStream( Global.FILEVERSION_1, key, 1 );
      si = new  PwsFileInputSocket( input );

      ok = si.attemptOpen( key );
      assertTrue( "socket open, 1", ok );

      reader = si.getRawFieldReader();

      // failure of secondary stream call
      try { 
         si.getBlockInputStream();
         fail( "secondary get blockstream failure: missing exception" );
      }
      catch ( Exception e )
      {
         assertTrue( "secondary get blockstream failure: wrong exception", 
               e instanceof IllegalStateException );
      }
      
      // failure of secondary reader call
      try { 
         si.getRawFieldReader();
         fail( "secondary get rawfieldreader failure: missing exception" );
      }
      catch ( Exception e )
      {
         assertTrue( "secondary get rawfieldreader failure: wrong exception", 
               e instanceof IllegalStateException );
      }
      
      // dump blockstream content
      while ( reader.hasNext() )
      {
         raw = (PwsRawField)reader.next();
         System.out.println( "Rawfield: T=" + raw.type + ", L=" + raw.length + ", data=" + 
               Util.bytesToHex( raw.data ) );
         
//         System.out.println( );
      }
      System.out.println();
   }
   catch ( Exception e )
   {
      fail( "IOException: " + e );
   }
}

}
