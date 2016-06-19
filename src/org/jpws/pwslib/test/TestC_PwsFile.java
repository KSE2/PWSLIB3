/*
 *  File: TestC_PwsFile.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 10.2015
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

package org.jpws.pwslib.test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.awt.Dimension;
import java.awt.event.KeyEvent;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import javax.swing.KeyStroke;

import org.jpws.pwslib.data.ContextFile;
import org.jpws.pwslib.data.PwsFile;
import org.jpws.pwslib.data.PwsFileFactory;
import org.jpws.pwslib.data.PwsPassphrase;
import org.jpws.pwslib.data.PwsRecord;
import org.jpws.pwslib.data.PwsRecordList;
import org.jpws.pwslib.exception.DuplicateEntryException;
import org.jpws.pwslib.exception.PasswordSafeException;
import org.jpws.pwslib.global.Global;
import org.jpws.pwslib.global.Util;
import org.jpws.pwslib.order.DefaultRecordWrapper;
import org.jpws.pwslib.persist.ApplicationAdapter;
import org.jpws.pwslib.persist.ByteArrayOutputStreamPws;
import org.junit.Test;
public class TestC_PwsFile {

public TestC_PwsFile() {
}

private PwsRecord createRecord (int type, int format ) {
	PwsRecord rec = new PwsRecord();
	
    switch ( type % 3 ) {
    case 0:
        rec.setTitle( "Hans Hase" );
        rec.setPassword( new PwsPassphrase( "abc" ) );
        rec.setUsername( "Hasimaus" );
        rec.setNotes( "Zugang zum Tresor, muß man sich verschaffen!" );
        rec.setAccessTime(789000012);
        if ( format > 2 ) {
           rec.setKeyboardShortcut(KeyStroke.getKeyStroke(KeyEvent.VK_W, 0));
        }
        break;
    case 1:
        rec.setTitle( "Maria Brenner" );
        rec.setPassword( new PwsPassphrase( "brezensieb" ) );
        rec.setUsername( "Brennermausi" );
        rec.setNotes( "Vor der Sieggötter Söhnen, tat ich Gesichte nun kund" );
        if ( format > 2 ) {
	        rec.setEmail("untersbacher.semmelbrot@cans.com");
	        rec.setProtectedEntry(true);
	        rec.setExtraField(30, rec.getSignature(), 0);
        }
        break;
    case 2:
        rec.setTitle( "Ursav Dominikus" );
        rec.setPassword( new PwsPassphrase( "llks092j3#" ) );
        rec.setUsername( "Segelboot" );
        rec.setNotes( "Unterdessen jedoch hatten auch die Robotschiffe Fahrt aufgenommen." );
        if ( format > 2 ) {
	        rec.setUrl("http://brezenbacher.sumpfkuchel/homemade.com");
	        rec.setAutotype("starte weisnichtwas");
        }
        break;
    default: return null; 
    }
    return rec;
}

private Collection<PwsRecord> getRecordCollection ( int size, int format ) 
{
	ArrayList<PwsRecord> list = new ArrayList<PwsRecord>();
	for ( int i = 0; i < size; i++ ) {
      // create data records if opted
      PwsRecord rec = createRecord(i, format);
      list.add( rec );
	}
	return list;
}

private Collection<PwsRecord> getDuplicateCollection(int size, int pos, int format) {
	if (size < 2 || pos > size-1 || pos < 0) 
		throw new IllegalArgumentException("improper argument setting");
	
	ArrayList<PwsRecord> list = new ArrayList<PwsRecord>();
	// add healthy records
	for (int i = 0; i < size-1; i++) {
		list.add(createRecord(i, format));
	}
	PwsRecord rec = list.get(pos);
	list.add(pos, rec);
	assertTrue("duplicate list setup", list.size() == size);
	return list;
}

private boolean sameContentLists (PwsRecordList l1, PwsRecordList l2) {
	boolean ok = l1.size() == l2.size();
	for ( Iterator<PwsRecord> it = l1.iterator(); it.hasNext() & ok; ) {
		ok &= l2.contains(it.next());
	}
	return ok;
}

@Test
public void test_initialisation () throws IOException, DuplicateEntryException {
	PwsFile f1;
	Collection<PwsRecord> col1;
	
	// empty constructor
	f1 = new PwsFile();
	test_init(f1, 0, false);

	// context file constructor
	PwsPassphrase pwd = new PwsPassphrase("Hello World");
	ApplicationAdapter fadp = Global.getStandardApplication();
	String filepath = "testdatei-pws.dat";
	ContextFile cf = new ContextFile(fadp, filepath);
	f1 = new PwsFile(cf, pwd);
	test_init(f1, 0, true);

	// adapter + path constructor
	f1 = new PwsFile(fadp, filepath, pwd);
	test_init(f1, 0, true);
	
	// local filepath constructor
	f1 = new PwsFile(filepath, pwd);
	test_init(f1, 0, true);
	
	// collection constructor
	col1 = getRecordCollection(5, 3);
	f1 = new PwsFile(col1);
	test_init(f1, 5, false);
	
	// array constructor
	PwsRecord[] arr = col1.toArray(new PwsRecord[col1.size()]);
	f1 = new PwsFile(arr);
	test_init(f1, 5, false);
	
	// record wrapper constructor
	DefaultRecordWrapper[] wrps = DefaultRecordWrapper.makeWrappers(arr, null);
	f1 = new PwsFile(wrps);
	test_init(f1, 5, false);

	// duplicate entry initialisation
	col1 = getDuplicateCollection(10, 5, 3);
	try {
		new PwsFile(col1);
		fail("missing exception on duplicate entry initialisation");
	} catch (DuplicateEntryException e) {
	}
	
	try {
		arr = col1.toArray(new PwsRecord[col1.size()]);
		new PwsFile(arr);
		fail("missing exception on duplicate entry initialisation");
	} catch (DuplicateEntryException e) {
	}
	
	try {
		wrps = DefaultRecordWrapper.makeWrappers(arr, null);
		new PwsFile(wrps);
		fail("missing exception on duplicate entry initialisation");
	} catch (DuplicateEntryException e) {
	}
}

/** Test the given PwsFile assuming it to be in initial state.
 * 
 * @param f1 PwsFile
 * @param size int the number of records expected
 * @param persist boolean whether persistent state should be defined
 * @throws IOException 
 */
private void test_init (PwsFile f1, int size, boolean persist) throws IOException {
	assertNotNull("file parameter missing", f1);
	assertTrue("file size not as expected", f1.size() == size);
	assertTrue("persistent state def. not as expected", f1.hasResource() == persist);
	assertTrue("last modified expected 0", f1.lastModified() == 0);
	Dimension dim = f1.getFileFormat();
	assertNotNull("file format (Dim) is missing", dim);
	assertNotNull("signature missing", f1.getSignature());
	assertTrue("checksum initial state must be true", f1.isChecksumVerified());
	assertTrue("source format must be zero", f1.getSourceFormat() == 0);
	assertTrue("file format (Dimension) not the latest", 
			dim.getWidth() == Global.FILEVERSION_LATEST_MAJOR);
	assertTrue("file format (Dimension) not the latest", 
			dim.getHeight() == Global.FILEVERSION_LATEST_MINOR);
	assertTrue("file format (int) not the latest", 
			f1.getFormatVersion() == Global.FILEVERSION_LATEST_MAJOR);
	assertNotNull("header field list missing", f1.getHeaderFields());
	assertTrue("false security loops minimum", 
			f1.getSecurityLoops() == PwsFile.SECURITY_ITERATIONS_MINIMUM);
	assertTrue("user options should be empty", f1.getUserOptions() == "");
	
	if (persist) {
		assertNotNull("IO-context missing", f1.getApplication());
		assertNotNull("filepath is missing", f1.getFilePath());
		assertNotNull("filename is missing", f1.getFileName());
		assertNotNull("context file is missing", f1.getContextFile());
		assertNotNull("passphrase is missing", f1.getPassphrase());
	}
}	

@Test
public void test_peristent_iostreams () throws IOException, PasswordSafeException {
	test_iostream(3);
//	test_iostream(2);
	test_iostream(1);
}

private void test_iostream ( int format ) throws IOException, PasswordSafeException {
	PwsFile f1, f2;
	Collection<PwsRecord> col1;
	PwsPassphrase pass1, key1;
	PwsRecord rec, rec2;
	byte[] sig1, data;
	
	col1 = getRecordCollection(20, format);
	f1 = new PwsFile(col1);
	f1.setFormatVersion(format);
	sig1 = f1.getDataSignature();
	data = null;
	
	// write output stream, no passphrase --> exception
	ByteArrayOutputStreamPws out = new ByteArrayOutputStreamPws();
	try {
		f1.write(out);
		fail("no exception on missing passphrase, format "+format);
	} catch (IllegalStateException e) {
	}

	// write output stream, with passphrase
	pass1 = new PwsPassphrase("einfache Omelette");
	f1.setPassphrase(pass1);
	try {
		f1.write(out);
		data = out.toByteArray();
		System.out.println("file-1 output data, size = " + data.length);
	} catch (IOException e) {
		e.printStackTrace();
		fail(e.toString());
	} catch (IllegalStateException e1) {
		fail();
	}

	// read
	ByteArrayInputStream input = new ByteArrayInputStream(data);
	f2 = PwsFileFactory.loadFile(input, pass1, format);
	// format 1
	if ( format == 1 ) {
		assertTrue("io-test: size mismatch, fo=1", f2.size() == f1.size());

		// searching for a title string in read database
		String search = f1.iterator().next().getTitle();
		key1 = f1.iterator().next().getPassword();
		boolean ok = false, passOk = false;
		for ( Iterator<PwsRecord> it = f2.iterator(); it.hasNext(); ) {
			rec = it.next();
			String hstr = rec.getTitle();
			PwsPassphrase key2 = rec.getPassword(); 
			assertNotNull(hstr);
			assertNotNull(key2);
			ok |= search.equals(hstr);
			passOk |= key1.equals(key2);
		}
		assertTrue("io-test: data mismatch (title not found in db), fo=1", ok);
		assertTrue("io-test: data mismatch (password not found in db), fo=1", passOk);

	// formats 2 + 3
	} else {
		if ( format > 2 ) {
			assertTrue("io-test: UUID mismatch, fo=" + format, f1.getUUID().equals(f2.getUUID()));
		}
		assertTrue("io-test: content not identical, fo=" + format, sameContentLists(f1, f2));
		boolean ok = true;
		int count = 0;
		for ( Iterator<PwsRecord> it = f1.iterator(); it.hasNext(); ) {
			rec = it.next();
			rec2 = f2.getRecord(rec);
			ok &= Util.equalArrays(rec.getSignature(), rec2.getSignature());
			assertTrue("io-test: record content mismatch (fo=" + format +"): " + count, ok);
			count++;
		}
		assertTrue("io-test: signature mismatch, fo=" + format, Util.equalArrays(sig1, f2.getDataSignature()));
	}
}
}
