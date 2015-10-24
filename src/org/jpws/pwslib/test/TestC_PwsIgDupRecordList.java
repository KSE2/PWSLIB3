package org.jpws.pwslib.test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import org.jpws.pwslib.crypto.SHA256;
import org.jpws.pwslib.data.PwsIgDupRecordList;
import org.jpws.pwslib.data.PwsPassphrase;
import org.jpws.pwslib.data.PwsRecord;
import org.jpws.pwslib.data.PwsRecordList;
import org.jpws.pwslib.exception.DuplicateEntryException;
import org.jpws.pwslib.global.UUID;
import org.jpws.pwslib.global.Util;
import org.junit.Test;

public class TestC_PwsIgDupRecordList {

public TestC_PwsIgDupRecordList() {
}

	

private PwsRecord createRecord (int type) {
	PwsRecord rec = new PwsRecord();
	
    switch ( type % 3 ) {
    case 0:
        rec.setTitle( "Hans Hase" );
        rec.setPassword( new PwsPassphrase( "abc" ) );
        rec.setUsername( "Hasimaus" );
        rec.setNotes( "Zugang zum Tresor, muß man sich verschaffen!" );
        break;
    case 1:
        rec.setTitle( "Maria Brenner" );
        rec.setPassword( new PwsPassphrase( "brezensieb" ) );
        rec.setUsername( "Brennermausi" );
        rec.setNotes( "Vor der Sieggötter Söhnen, tat ich Gesichte nun kund" );
        break;
    case 2:
        rec.setTitle( "Ursav Dominikus" );
        rec.setPassword( new PwsPassphrase( "llks092j3#" ) );
        rec.setUsername( "Segelboot" );
        rec.setNotes( "Unterdessen jedoch hatten auch die Robotschiffe Fahrt aufgenommen." );
        break;
    default: return null; 
    }
    return rec;
}


private Collection<PwsRecord> getDuplicateCollection(int size, int pos) {
	if (size < 2 || pos > size-1 || pos < 0) 
		throw new IllegalArgumentException("improper argument setting");
	
	ArrayList<PwsRecord> list = new ArrayList<PwsRecord>();
	// add healthy records
	for (int i = 0; i < size-1; i++) {
		list.add(createRecord(i));
	}
	PwsRecord rec = list.get(pos);
	list.add(pos, rec);
	assertTrue("duplicate list setup", list.size() == size);
	return list;
}


private Collection<PwsRecord> getRecordCollection (int size) 
{
	ArrayList<PwsRecord> list = new ArrayList<PwsRecord>();
	for ( int i = 0; i < size; i++ ) {
      // create data records if opted
      PwsRecord rec = createRecord(i % 3);
      list.add( rec );
	}
	return list;
}


/** Tests methods addRecord() and addRecordValid().
 */
@Test
public void test_addRecord () throws DuplicateEntryException {
	Collection<PwsRecord> col1;
	PwsIgDupRecordList li1;
	PwsRecord rec;
	byte[] sig, sig2;
	
	// test on empty list
	li1 = new PwsIgDupRecordList();
	rec = createRecord(0);
	sig = rec.getSignature();
	UUID recID = rec.getRecordID();
	li1.addRecord(rec);
	test_state(li1, 1, true, true, null, "(addRecord-1)");
	sig2 = li1.getSignature();
	
	// probe containment and value preservation
	assertTrue("list does not contain record after addRecord()", li1.contains(rec));
	assertTrue("contained record has changed content", Util.equalArrays(sig, 
			li1.getRecord(recID).getSignature()));

	// tolerance of duplicate insertion attempt (without effect)
	li1.resetModified();
	li1.addRecord(rec);
	test_state(li1, 1, false, true, sig2, "(addRecord-2)");
	
	li1.addRecordValid(rec);
	test_state(li1, 1, false, true, sig2, "(addRecordValid-1)");
	
	// may insert invalid record
	rec = new PwsRecord();
	li1.addRecord(rec);
	test_state(li1, 2, true, false, null, "(addRecord-3)");
	
	// probe containment
	assertTrue("list does not contain record after addRecord()", li1.contains(rec));

	// probe exception on invalid entry
	try {
		li1.addRecordValid(rec);
		fail("fails to throw exception on entry of invalid record (addRecordValid-2)");
	} catch( IllegalArgumentException e) {
	}
	
	// probe addRecordValid
	rec = createRecord(1);
	li1.addRecordValid(rec);
	test_state(li1, 3, true, false, null, "(addRecordValid-3)");
	
	// probe containment
	assertTrue("list does not contain record after addRecordValid()", li1.contains(rec));

	// probe adding on preset list
	col1 = getRecordCollection(3);
	li1 = new PwsIgDupRecordList(col1);
	li1.addRecord(rec);
	test_state(li1, 4, true, true, null, "(addRecord-4)");

	// probe containment
	assertTrue("list does not contain record after addRecord()", li1.contains(rec));
}



private void test_state ( PwsRecordList list, 
		                  int size,
		                  boolean modified,
		                  boolean mustValid,
		                  byte[] signature,
		                  String location
		                  )	
{
	if ( list == null )
		throw new NullPointerException();

	String locStr = location == null ? "" : " (" + location + ") ";
	
	int count = list.getRecordCount();
	assertTrue("test-state: size mismatch, expected " + size +", have " + count 
				+ locStr, size == count);
	assertTrue("test-state: modified state wrong, expected: " + modified +locStr, 
			    modified == list.isModified());
	
	// test iterator counting
	count = 0;
	for (Iterator<PwsRecord> it = list.iterator(); it.hasNext(); it.next()) {
		count++;
	}
	assertTrue("test-state: iterator count mismatch, expected " + size +
			", have " + count + locStr, size == count);
	
	boolean expectEmpty = size == 0; 
	assertTrue("test-state: isEmpty() false result, expected: "+ expectEmpty, 
			list.isEmpty() == expectEmpty);
	
	if ( mustValid )
	assertFalse("test-state: has illegal invalid recs: " + list.countInvalid()+locStr, 
			    list.hasInvalidRecs());

	assertNotNull("UUID not present"+locStr, list.getUUID());
	
	if ( signature != null ) 
	assertTrue("List signature not as expected"+locStr, Util.equalArrays(
			    signature, list.getSignature()));
	
	
}



/** Tests method addCollection().
 */
@Test
public void test_add_record_collection () throws DuplicateEntryException {
	Collection<PwsRecord> col1, col2;
	PwsIgDupRecordList li1, li2, li3;

	col1 = getRecordCollection(6);
	col2 = getRecordCollection(6);
	li1 = new PwsIgDupRecordList(col1);
	li2 = new PwsIgDupRecordList();

	// determine col2 data signature
	SHA256 sha = new SHA256(); 
	for (PwsRecord rec : col2) {
		sha.update(rec.getSignature());
	}
	byte[] sig = sha.digest();
	
	// test add to preset list
	li3 = (PwsIgDupRecordList)li1.addCollection(col2);
	test_state(li1, col1.size()+col2.size(), true, true, null, "add coll 1");
	assertTrue("fails to contain added collection", li1.containsCollection(col2));
	assertTrue("fails to contain preset collection", li1.containsCollection(col1));
	assertTrue("should return parameter record list", li3 == li1);
	
	// control col2 data signature
	sha = new SHA256(); 
	for (PwsRecord rec : col2) {
		sha.update( li1.getRecord(rec.getRecordID()).getSignature() );
	}
	assertTrue("data signature failure of added collection", Util.equalArrays(
			sig, sha.digest()));
	
	// test add to empty list
	li2.addCollection(col1);
	test_state(li2, col1.size(), true, true, null, "add coll 2");
	assertTrue("fails to contain added collection", li2.containsCollection(col1));
	assertFalse("falsely contains alien collection", li2.containsCollection(col2));
	
	// test null parameter
	li2.resetModified();
	li2.addCollection(null);
	test_state(li2, col1.size(), false, true, null, "add null col");

	// test exception on duplicates
	li2.addCollection(col1);
	test_state(li2, col1.size(), false, true, null, "duplicate 1");
	
	// test duplicate in parameter list
	col2 = getDuplicateCollection(5,2);
	li2.addCollection(col2);
	test_state(li2, col1.size()+4, true, true, null, "duplicate 2");
}



/** Tests method addRecordList().
 */
@Test
public void test_add_record_list () throws DuplicateEntryException {
	Collection<PwsRecord> col1, col2;
	PwsIgDupRecordList li1, li2, li3;

	col1 = getRecordCollection(6);
	col2 = getRecordCollection(6);
	li1 = new PwsIgDupRecordList(col1);
	li2 = new PwsIgDupRecordList(col2);

	// test add to preset list
	li3 = (PwsIgDupRecordList)li1.addRecordList(li2);
	test_state(li1, col1.size()+col2.size(), true, true, null, "add list 1");
	assertTrue("fails to contain added record-list", li1.containsCollection(col2));
	assertTrue("fails to contain preset record-list", li1.containsCollection(col1));
	assertTrue("should return parameter record list", li3 == li1);
	
	// test add to empty list
	li1 = new PwsIgDupRecordList(col1);
	li2 = new PwsIgDupRecordList();
	li2.addRecordList(li1);
	test_state(li2, col1.size(), true, true, null, "add list 2");
	assertTrue("fails to contain added collection", li2.containsCollection(col1));
	assertFalse("falsely contains alien collection", li2.containsCollection(col2));
	
	// test null parameter
	li2.resetModified();
	li2.addRecordList(null);
	test_state(li2, col1.size(), false, true, null, "add null col");

	// test no exception on duplicates
	li2.addRecordList(li1);
	test_state(li2, col1.size(), false, true, null, "duplicate 1");
}



/** Tests methods replaceContent() and replaceFrom().
 * @throws DuplicateEntryException 
 */
@Test
public void test_replace () throws DuplicateEntryException {
	PwsIgDupRecordList li1, li2;
	Collection<PwsRecord> col1, col2, col3;
	byte[] sig2;

	col1 = getRecordCollection(8);
	col2 = getRecordCollection(6);
	li1 = new PwsIgDupRecordList(col1);
	li2 = new PwsIgDupRecordList(col2);
	sig2 = li2.getSignature();
	
	// test replaceContent with values
	PwsRecord[] arr = li2.toArray();
	li1.replaceContent(arr);
	test_state(li1, col2.size(), true, true, null, "replace content 1");
	assertTrue("replaceContent does not place correct content", 
			Util.equalArrays(sig2, li1.getSignature()));
	
	// test replaceContent with empty array
	li1.resetModified();
	li1.replaceContent(new PwsRecord[0]);
	test_state(li1, 0, true, true, null, "replace content 2");
	
	// test replaceContent with null parameter
	li2.replaceContent(null);
	test_state(li2, 0, true, true, null, "replace content 3");

	// test replace with duplicate list
	col3 = getDuplicateCollection(5,2);
	arr = col3.toArray(new PwsRecord[0]);
	li1.resetModified();
	li1.replaceContent(arr);
	test_state(li1, 4, true, true, null, "replace content 4");
}


}
