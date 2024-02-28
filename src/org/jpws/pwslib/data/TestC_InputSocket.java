/*
 *  File: TestC_InputSocket.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 27.08.2006
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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.jpws.pwslib.exception.UnsupportedFileVersionException;
import org.jpws.pwslib.exception.WrongFileVersionException;
import org.jpws.pwslib.global.Global;

import junit.framework.TestCase;
import kse.utilclass.misc.DirectByteOutputStream;
import kse.utilclass.misc.Util;

/**
 *  
 */
public class TestC_InputSocket  extends TestCase {

   public TestC_InputSocket () {
      super();
   }

   public TestC_InputSocket ( String name ) {
      super( name );
   }

public InputStream getPwsInputStream( int version, PwsPassphrase key ) {
   return getPwsInputStream( version, key, 1 );
}

/** Returns a list of PwsRecord with population depending on the parameter.
 *  
 * @param dataCode int 0 = empty, 1 = 1 entry, 2 = 3 entries
 * @return {@code PwsRecordList}
 */
public PwsRecordList getPwsRecordList ( int dataCode ) {
   PwsRecordList list = new PwsRecordList();
   PwsRecord rec;
   
   try {
      // create data records if opted
	  if (dataCode > 0) { 
         //
         rec = new PwsRecord();
         rec.setTitle( "Hans Hase" );
         rec.setPassword( new PwsPassphrase( "abc" ) );
         rec.setUsername( "Hasimaus" );
         rec.setNotes( "Zugang zum Tresor, mu� man sich verschaffen!" );
         list.addRecord( rec );
	  }

	  if (dataCode > 1) { 
         //
         rec = new PwsRecord();
         rec.setTitle( "Edith Kleinhammer" );
         rec.setPassword( new PwsPassphrase( "abraham" ) );
         rec.setUsername( "Kleinhase" );
         rec.setNotes( "Einer kam im Abendschein." );
         list.addRecord( rec );
         
         //
         rec = new PwsRecord();
         rec.setTitle( "Maximilian Sinnrein" );
         rec.setPassword( new PwsPassphrase( "karuna 333" ) );
         rec.setUsername( "Seltsamer Hase" );
         rec.setNotes( "Im Morgenlicht sah man einen Reiter von Ferne aus dem Nebel auftauchen." );
         list.addRecord( rec );
	  }

   } catch ( Exception e ) {
      fail( "Exception during creation of record list: " + e );
   }
   
   return list;
}

public void testCase_blockwrite ( int keyLength, int dataSize ) throws IOException  {
	PwsPassphrase key = new PwsPassphrase("pwbc-123");
	DirectByteOutputStream out = new DirectByteOutputStream();
	PwsFileOutputSocket outSocket = new PwsFileOutputSocket(out, key, null);
	outSocket.setKeySecurity(keyLength);
	PwsBlockOutputStream blockOut = outSocket.getBlockOutputStream();

	// write a block of cleartext to the output socket
	int blocksize = outSocket.getBlocksize();
	if (dataSize % blocksize > 0) {
		dataSize = (dataSize / blocksize + 1) * blocksize; 
	}
	byte[] data = Util.randBytes(dataSize);
	blockOut.writeBlocks(data);
	blockOut.close();

	// read back from encrypted results (regular)
	InputStream in = new ByteArrayInputStream(out.getBuffer(), 0, out.size());
	PwsFileInputSocket inSocket = new PwsFileInputSocket(in, keyLength);
	try {
		boolean open = inSocket.attemptOpen(key, Global.FILEVERSION_3);
		assertTrue("file open error", open);
	} catch (WrongFileVersionException e) {
		e.printStackTrace();
		fail("error: wrong file version");
	} catch (UnsupportedFileVersionException e) {
		e.printStackTrace();
		fail("error: unsupported file version");
	}
	PwsBlockInputStream inStream = inSocket.getBlockInputStream();
	byte[] readData = inStream.readBlocks(dataSize / blocksize);
	
	assertTrue("data read error", Util.equalArrays(data, readData));
	
	// read from encrypted data w/ wrong key-length (-> open attempt fails)
	int rkl = 0;
	switch (keyLength) {
	case 256: rkl = 128; break;
	case 128: rkl = 192; break;
	case 64: rkl = 256; break;
	case 192: rkl = 64; break;
	}
	
	in = new ByteArrayInputStream(out.getBuffer(), 0, out.size());
	inSocket = new PwsFileInputSocket(in, rkl);
	try {
		boolean open = inSocket.attemptOpen(key, Global.FILEVERSION_3);
		assertFalse("file open error", open);
	} catch (WrongFileVersionException e) {
		e.printStackTrace();
		fail("error: wrong file version");
	} catch (UnsupportedFileVersionException e) {
		e.printStackTrace();
		fail("error: unsupported file version");
	}
	
}

public InputStream getPwsInputStream( int version, PwsPassphrase key, PwsRecordList list ) {
   // construct
   ByteArrayOutputStream out = new ByteArrayOutputStream();
   try {
      PwsFileFactory.saveFile( list.iterator(), out, key, null, 8000, version );
      
   } catch ( IOException e ) {
      throw new IllegalStateException( "IOException: " + e );
   }
   
   // return resulting data block
   byte[] data = out.toByteArray();
   return new ByteArrayInputStream( data ); 
}

public InputStream getPwsInputStream( int version, PwsPassphrase key, int dataCode ) {
   return getPwsInputStream( version, key, getPwsRecordList( dataCode) );
}

public void test_construct () throws IOException {
   PwsFileInputSocket si;
   PwsPassphrase key;
   InputStream input;
   
   // test null parameter
   try { 
      new PwsFileInputSocket( null );
      fail( "socket init failure: expected NullPointerException" );
   } catch ( NullPointerException e ) {
   }
   
   // test illegal key-length value
   key = new PwsPassphrase("abc");
   input = getPwsInputStream(0, key);

   try { 
      new PwsFileInputSocket( input, 255 );
      fail( "socket init failure: expected IllegalArgumentException" );
   } catch ( IllegalArgumentException e ) {
   }
   
   try { 
      new PwsFileInputSocket( input, 0 );
      fail( "socket init failure: expected IllegalArgumentException" );
   } catch ( IllegalArgumentException e ) {
   }
   
   try { 
      new PwsFileInputSocket( input, -64 );
      fail( "socket init failure: expected IllegalArgumentException" );
   } catch ( IllegalArgumentException e ) {
   }
   
   // test correct creation
   input = getPwsInputStream( Global.FILEVERSION_3, key );
   si = new  PwsFileInputSocket( input, 256 );
   assertFalse( "closed socket, open state is false", si.isOpen() );
   assertTrue( "closed socket, no file version", si.getFileVersion() == 0 );
   assertTrue("false key-length", si.getKeySecurity() == 256);
   assertTrue(si.getBlocksize() == 0);
   assertTrue(si.getIterations() == 0);
   assertNull(si.getCalcChecksum());
   assertNull(si.getReadChecksum());
   assertNull(si.getFileUUID());
   assertNull(si.getHeaderFields());
   
   si = new  PwsFileInputSocket( input, 128 );
   assertTrue("false key-length", si.getKeySecurity() == 128);

   si = new  PwsFileInputSocket( input, 64 );
   assertTrue("false key-length", si.getKeySecurity() == 64);
   
   // IllegalStateException when socket is closed  
   try { 
      si.getBlockInputStream();
      fail( "closed socket get blockstream failure: expected IllegalStateException" );
   } catch ( Exception e ) {
      assertTrue( "closed socket get blockstream failure: wrong exception", 
            e instanceof IllegalStateException );
   }
   
   try { 
      si.getRawFieldReader();
      fail( "closed socket get rawfieldreader failure: expected IllegalStateException" );
   } catch ( Exception e ) {
      assertTrue( "closed socket get rawfieldreader failure: wrong exception", 
            e instanceof IllegalStateException );
   }
}

public void test_key_length () throws IOException {

   testCase_blockwrite(256, 1000);
   testCase_blockwrite(128, 2000);
   testCase_blockwrite(64, 2000);
   testCase_blockwrite(192, 4000);
}

public void test_OpenAttempt () {
   PwsFileInputSocket si;
   PwsPassphrase key;
   InputStream input;
   boolean ok;
   int dataCode, count;

   // test correct creation
   key = new PwsPassphrase( "abc" );
   
   try {
      // *** VERSION 3 TESTING ***
      count = 0;
      while ( count < 3 ) {
         dataCode = count;
         
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
         assertTrue("false key-length", si.getKeySecurity() == 256);
         assertTrue("false blocksize: " + si.getBlocksize(), si.getBlocksize() == 16);
         assertTrue(si.getIterations() == 8000);
         assertNotNull(si.getCalcChecksum());
         assertNotNull(si.getReadChecksum());
         assertNotNull(si.getFileUUID());
         assertNotNull(si.getHeaderFields());
         
         // specific V3-open on V3 file
         input = getPwsInputStream( Global.FILEVERSION_3, key, dataCode );
         si = new  PwsFileInputSocket( input );
   
         ok = si.attemptOpen( new PwsPassphrase(), Global.FILEVERSION_3 );
         assertFalse( "V3, socket open fails on wrong password, 2", ok );
         
         ok = si.attemptOpen( new PwsPassphrase( "abc" ), Global.FILEVERSION_3 );
         assertTrue( "V3, socket open succeeds on good password, 2", ok );
         
         assertTrue( "V3, socket open, open state, 2", si.isOpen() );
         assertTrue( "V3, socket open, correct file version, 2", si.getFileVersion() == Global.FILEVERSION_3 );
         
         count++;
      } // while
      
      
   } catch ( IOException e ) {
      fail( "IOException: " + e );
   } catch ( WrongFileVersionException e ) {
      fail( "WrongFileVersionException" );
   } catch ( UnsupportedFileVersionException e ) {
      fail( "UnsupportedFileVersionException" );
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
      input = getPwsInputStream( Global.FILEVERSION_3, key, 1 );
      si = new  PwsFileInputSocket( input );

      ok = si.attemptOpen( key );
      assertTrue( "socket open, 1", ok );

      reader = si.getRawFieldReader();

      // failure of secondary stream call
      try { 
         si.getBlockInputStream();
         fail( "secondary get blockstream failure: missing exception" );
      } catch ( Exception e ) {
         assertTrue( "secondary get blockstream failure: wrong exception", 
               e instanceof IllegalStateException );
      }
      
      // failure of secondary reader call
      try { 
         si.getRawFieldReader();
         fail( "secondary get rawfieldreader failure: missing exception" );
      } catch ( Exception e ) {
         assertTrue( "secondary get rawfieldreader failure: wrong exception", 
               e instanceof IllegalStateException );
      }
      
      // dump blockstream content
      while ( reader.hasNext() )  {
         raw = (PwsRawField)reader.next();
         System.out.println( "Rawfield: T=" + raw.type + ", L=" + raw.length + ", data=" + 
               Util.bytesToHex( raw.getData() ) );
         
//         System.out.println( );
      }
      System.out.println();

   } catch ( Exception e ) {
	  e.printStackTrace();
      fail( "IOException: " + e );
   }
}

}
