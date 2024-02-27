/*
 *  File: TestC_RecordList.java
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

import org.jpws.pwslib.data.PwsFileEvent;
import org.jpws.pwslib.data.PwsFileListener;
import org.jpws.pwslib.data.PwsPassphrase;
import org.jpws.pwslib.data.PwsRecord;
import org.jpws.pwslib.data.PwsRecordList;
import org.jpws.pwslib.exception.DuplicateEntryException;
import org.jpws.pwslib.exception.NoSuchRecordException;
import org.jpws.pwslib.global.UUID;
import org.jpws.pwslib.order.DefaultRecordWrapper;
import org.junit.Test;

import kse.utilclass.misc.Log;
import kse.utilclass.misc.SHA256;
import kse.utilclass.misc.Util;



public class TestC_RecordList {

	PwsFileListener testFileListener = new PwsFileListener() {
		
		@Override
		public void fileStateChanged(PwsFileEvent evt) {
		}
	};
	
public TestC_RecordList() {
	Log.setDebugLevel(2);
	Log.setLogLevel(2);
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

private PwsRecord createRecord (int type) {
	PwsRecord rec = new PwsRecord();
	
    switch ( type % 3 ) {
    case 0:
        rec.setTitle( "Hans Hase" );
        rec.setPassword( new PwsPassphrase( "abc" ) );
        rec.setUsername( "Hasimaus" );
        rec.setNotes( "Zugang zum Tresor, mu� man sich verschaffen!" );
        break;
    case 1:
    	rec.setGroup("Stadthasen");
        rec.setTitle( "Maria Brenner" );
        rec.setPassword( new PwsPassphrase( "brezensieb" ) );
        rec.setUsername( "Brennermausi" );
        rec.setNotes( "Vor der Siegg�tter S�hnen, tat ich Gesichte nun kund" );
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

private boolean sameContentLists (PwsRecordList l1, PwsRecordList l2) {
	boolean ok = l1.size() == l2.size();
	for ( Iterator<PwsRecord> it = l1.iterator(); it.hasNext() & ok; ) {
		ok &= l2.contains(it.next());
	}
	return ok;
}

private boolean sameContentColls (Collection<PwsRecord> l1, Collection<PwsRecord> l2) {
	boolean ok = l1.size() == l2.size();
	for ( Iterator<PwsRecord> it = l1.iterator(); it.hasNext() & ok; ) {
		ok &= l2.contains(it.next());
	}
	return ok;
}

private void addGroupedRecords( PwsRecordList list, String group, int recs ) {
	for ( int i = 0; i < recs; i++ ) {
		PwsRecord rec = createRecord(i);
		rec.setGroup(group);
		try { list.addRecord(rec);
		} catch (DuplicateEntryException e) {
		}
	}
}

private PwsRecordList createGroupedRecordList () {
	PwsRecordList li1 = new PwsRecordList();
	addGroupedRecords(li1, "Handlanger.Schutzschieber", 5);
	addGroupedRecords(li1, "Handlanger.Brecheisen", 5);
	addGroupedRecords(li1, "Eselsscheunen", 5);
	addGroupedRecords(li1, "Kurzweilige.Handdamen", 5);
	addGroupedRecords(li1, "", 5);
	assertTrue("group creation", li1.size() == 25);
	return li1;
}

private PwsRecordList makeRecordList (Iterator<PwsRecord> it) 
		throws DuplicateEntryException {
	PwsRecordList list = new PwsRecordList();
	for (;it.hasNext();) {
		list.addRecord(it.next());
	}
	return list;
}

@Test
public void test_merge () throws NoSuchRecordException {
   PwsRecordList li1, li2, li3, li4;
   PwsRecord rec;
   UUID uuid;
   String grpValue, newGrpValue;
   int modus, size;	
   
   li1 = createGroupedRecordList();
   li2 = createGroupedRecordList();
   size = li1.size();
   
   // merge 2 disparate lists
   li3 = li1.copy();
   modus = PwsRecordList.MERGE_PLAIN;
   li4 = li3.merge(li2, modus, false)[0];
   assertTrue("unexpected record exclusion", li4.isEmpty());
   assertTrue("false resulting size", li3.size() == size*2);

   // merge same list (plain)
   li3 = li1.copy();
   modus = PwsRecordList.MERGE_PLAIN;
   li4 = li3.merge(li3, modus, false)[0];
   assertTrue("unexpected record exclusion", li4.size() == 0);
   assertTrue("false resulting size", li3.size() == size);

   // merge list copy with modifications (exclude)
   li3 = li1.copy();
   rec = li3.iterator().next();
   uuid = rec.getRecordID();
   rec.setTitle("Krummer Hund");
   li3.updateRecord(rec);
   modus = PwsRecordList.MERGE_PLAIN;
   li4 = li3.merge(li1, modus, false)[0];
   assertTrue("unsufficient record exclusion", li4.size() == 1);
   assertTrue("missing excluded record", li4.contains(uuid));

   // merge list copy with modifications (exclude)
   modus = PwsRecordList.MERGE_INCLUDE;
   li4 = li3.merge(li1, modus, false)[0];
   assertTrue("unexpected record exclusion", li4.isEmpty());
   assertTrue("missing included record", li3.contains(uuid));
   assertTrue("false resulting size", li3.size() == size);

   
}

/** This tests method renameGroup().
 */
@Test
public void test_rename_group () throws DuplicateEntryException {
	PwsRecordList li1, li2;
	String grpValue, newGrpValue;
	
	li1= createGroupedRecordList();
	
	// rename existing group to new
	grpValue = "Handlanger.Brecheisen";
	newGrpValue = "Eselsbr�cken";
	li2 = li1.renameGroup(grpValue, newGrpValue);
	assertNotNull("should return a value", li2);
	assertTrue("result list size", li2.size() == 5);
	for (PwsRecord rec : li2.toArray()) {
		assertTrue("false set (value)",rec.getGroup().equals(newGrpValue));
	}
	assertTrue("group value not contained", li1.containsGroup(newGrpValue));
	assertFalse("missed to rename record group", li1.containsGroup(grpValue));
	assertTrue(li1.getGrpRecordCount(newGrpValue, true) == 5);
	
	// rename existing group to existing group
	grpValue = "Eselsbr�cken";
	newGrpValue = "";
	li2 = li1.renameGroup(grpValue, newGrpValue);
	assertNotNull("should return a value", li2);
	assertTrue("result list size", li2.size() == 5);
	for (PwsRecord rec : li2.toArray()) {
		assertTrue("false set (value)",rec.getGroup() == null);
	}
	assertTrue("group value not contained", li1.containsGroup(newGrpValue));
	assertFalse("missed to rename record group", li1.containsGroup(grpValue));
	assertTrue(li1.getGrpRecordCount(newGrpValue, true) == 10);
	
	// rename not-existing group to new
	grpValue = "Esels";
	newGrpValue = "Neue Gruppe";
	li2 = li1.renameGroup(grpValue, newGrpValue);
	assertNotNull("should return a value", li2);
	assertTrue("result list size", li2.size() == 0);
	assertFalse("false group value contained", li1.containsGroup(newGrpValue));
	assertFalse("contains unknown group", li1.containsGroup(grpValue));
	assertTrue(li1.getGrpRecordCount(newGrpValue, true) == 0);
	
	// null par1: no operation
	li2 = li1.renameGroup(null, newGrpValue);
	assertNotNull("should return a value", li2);
	assertTrue("result list size", li2.size() == 0);
	assertFalse("false group value contained", li1.containsGroup(newGrpValue));
	
	// null par2: shift to ""
	grpValue = "Eselsscheunen";
	newGrpValue = "";
	li2 = li1.renameGroup(grpValue, null);
	assertNotNull("should return a value", li2);
	assertTrue("result list size", li2.size() == 5);
	for (PwsRecord rec : li2.toArray()) {
		assertTrue("false set (value)",rec.getGroup() == null);
	}
	assertTrue("group value not contained", li1.containsGroup(newGrpValue));
	assertFalse("missed to rename record group", li1.containsGroup(grpValue));
	assertTrue(li1.getGrpRecordCount(newGrpValue, true) == 15);
}

/** This tests methods getGroup(), moveRecords().
 */
@Test
public void test_move_records () throws DuplicateEntryException {
	PwsRecordList li1, li2, li3;
	DefaultRecordWrapper set[], res[];
	PwsRecord rec2;
	List<String> names;
	String grpValue, newGrpValue, hstr;
	
	li1= createGroupedRecordList();

	// test getGroup
	li2 = li1.getGroup(null);
	assertTrue("getGroup result error", li2.isEmpty());
	li2 = li1.getGroup("Kaninchen");
	assertTrue("getGroup result error", li2.isEmpty());
	li2 = li1.getGroup("Esels");
	assertTrue("getGroup result error", li2.isEmpty());
	li2 = li1.getGroup("Handlanger");
	assertTrue("getGroup result error", li2.size() == 10);
	
	// test getGroup value
	grpValue = "Eselsscheunen";
	set = li1.getGroup(grpValue).toRecordWrappers(null);
	assertTrue("false getGroup() set (size)", set.length == 5);
	for (DefaultRecordWrapper wrp : set) {
		assertTrue("false getGroup() set (value)", wrp.getRecord().getGroup().equals(grpValue));
	}
	
	// test move records (keep-paths == false)
	li3 = li1.copy();
	newGrpValue = "Handlanger.Stichspaten";
	res = li3.moveRecords(set, newGrpValue, false);
	assertTrue("false result length in moveRecords", res.length == 5);
	for (DefaultRecordWrapper wrp : res) {
		assertTrue("false set (value)", wrp.getRecord().getGroup().equals(newGrpValue));
	}
	for (DefaultRecordWrapper wrp : set) {
		assertTrue("false set (value)", wrp.getRecord().getGroup().equals(newGrpValue));
	}
	for (DefaultRecordWrapper wrp : set) {
		assertTrue("false set (value)", 
				li3.getRecord(wrp.getRecordID()).getGroup().equals(newGrpValue));
	}
	
	// test move records (keep-paths == true)
	li3 = li1.copy();
	res = li3.moveRecords(set, newGrpValue, true);
	assertTrue("false result length in moveRecords", res.length == 5);
	hstr = newGrpValue.concat(".Eselsscheunen");
	for (DefaultRecordWrapper wrp : res) {
		assertTrue("false set (value)", wrp.getRecord().getGroup().equals(hstr));
	}
	for (DefaultRecordWrapper wrp : set) {
		assertTrue("false set (value)", wrp.getRecord().getGroup().equals(hstr));
	}
	for (DefaultRecordWrapper wrp : set) {
		assertTrue("false set (value)", 
				li3.getRecord(wrp.getRecordID()).getGroup().equals(hstr));
	}
	
	// move on empty group
	li3 = li1.copy();
	res = li3.moveRecords(set, "", false);
	assertTrue("false result length in moveRecords", res.length == 5);
	for (DefaultRecordWrapper wrp : set) {
		assertNull("false set (value)", li3.getRecord(wrp.getRecordID()).getGroup());
	}
	
	// move on null group
	li3 = li1.copy();
	res = li3.moveRecords(set, null, false);
	assertTrue("false result length in moveRecords", res.length == 5);
	for (DefaultRecordWrapper wrp : set) {
		assertNull("false set (value)", li3.getRecord(wrp.getRecordID()).getGroup());
	}
	
	// move on null set
	li3 = li1.copy();
	res = li3.moveRecords(null, "", false);
	assertNull("result should be null", res);
	
	// move on empty set
	li3 = li1.copy();
	res = li3.moveRecords(new DefaultRecordWrapper[0], "", false);
	assertNull("result should be null", res);
	
}

/** Tests containsGroup(), getGroupCount(), getGrpRecordCount(), getGroupList(),
 *  getGroupedRecords().
 */
@Test
public void test_group_methods () throws DuplicateEntryException {
	PwsRecordList li1, li2;
	PwsRecord rec2;
	List<String> names;
	String grpValue;
	
	li1= createGroupedRecordList();
	
	// test getGroupCount
	assertTrue("false getGroupCount value", li1.getGroupCount() == 5);
	
	// test containsGroup
	assertTrue(li1.containsGroup("Handlanger.Schutzschieber"));
	assertTrue(li1.containsGroup("Eselsscheunen"));
	assertTrue(li1.containsGroup("Kurzweilige.Handdamen"));
	assertTrue(li1.containsGroup("Kurzweilige"));
	assertTrue(li1.containsGroup(""));
	assertFalse(li1.containsGroup(null));
	assertFalse(li1.containsGroup("Esels"));
	
	li2 = new PwsRecordList();
	assertFalse(li2.containsGroup("Eselsscheunen"));
	assertFalse(li2.containsGroup(""));
	assertFalse(li2.containsGroup(null));
	
	// group list 1
	names = li1.getGroupList();
	assertTrue("incorrect group list size", names.size() == 7);
	assertTrue("missing group name", names.contains("Handlanger.Schutzschieber"));
	assertTrue("missing group name", names.contains("Handlanger"));
	assertTrue("missing group name", names.contains("Eselsscheunen"));
	assertTrue("missing group name", names.contains("Kurzweilige.Handdamen"));
	assertTrue("missing group name", names.contains("Kurzweilige"));
	assertTrue("missing group name", names.contains(""));
	assertFalse("missing group name", names.contains(null));
	
	// group list 2
	li2 = new PwsRecordList();
	assertTrue("incorrect group list size", li2.getGroupList().isEmpty());
	rec2 = createRecord(0);
	rec2.setGroup("Gruppe-1");
	li2.addRecord(rec2);
	names = li2.getGroupList();
	assertTrue("incorrect group list size", names.size() == 1);
	assertTrue("missing group name", names.contains("Gruppe-1"));
	
	// test getGroupedRecords
	grpValue = "Handlanger.Schutzschieber";
	Iterator<PwsRecord> it = li1.getGroupedRecords(grpValue, true);
	li2 = makeRecordList(it);
	assertTrue("false group size", li2.size() == 5);
	for (PwsRecord rec : li2.toList()) {
		assertTrue("false record grouped, getGroupedRecords()", 
				rec.getGroup() == grpValue);
	}
	// subgroup inclusion
	grpValue = "Handlanger";
	it = li1.getGroupedRecords(grpValue, true);
	assertTrue("false group size", makeRecordList(it).size() == 10);

	grpValue = "Handlanger.Schutz";
	it = li1.getGroupedRecords(grpValue, true);
	assertTrue("false group size", makeRecordList(it).size() == 0);
	it = li1.getGroupedRecords(grpValue, false);
	assertTrue("false group size", makeRecordList(it).size() == 5);

	it = li1.getGroupedRecords(null, true);
	assertTrue("false group size", makeRecordList(it).isEmpty());
	it = li1.getGroupedRecords(null, false);
	assertTrue("false group size", makeRecordList(it).isEmpty());
	it = li1.getGroupedRecords("", true);
	assertTrue("false group size", makeRecordList(it).size() == 5);
	it = li1.getGroupedRecords("", false);
	assertTrue("false group size", makeRecordList(it).size() == li1.size());

	// test getGrpRecordCount
	grpValue = "Handlanger.Schutzschieber";
	assertTrue("false group count", li1.getGrpRecordCount(grpValue, true) == 5);
	assertTrue("false group count", li1.getGrpRecordCount("", true) == 5);
	assertTrue("false group count", li1.getGrpRecordCount(null, true) == 0);

	// test getGrpRecordCount precision
	grpValue = "Handlanger.Schutz";
	assertTrue("false group count", li1.getGrpRecordCount(grpValue, true) == 0);
	assertTrue("false group count", li1.getGrpRecordCount(grpValue, false) == 5);
	assertTrue("false group count", li1.getGrpRecordCount("", false) == li1.size());
	
	
	// test removeGroup
	grpValue = "Handlanger.Schutzschieber";
	li2 = li1.removeGroup(grpValue);
	assertTrue("mismatch in number of removed records (GROUP remove)", li2.size() == 5);
	assertFalse(li1.containsGroup(grpValue));
	// check result list
	for (PwsRecord rec : li2.toList()) {
		assertTrue("false record removed in removeGroup()", rec.getGroup() == grpValue);
	}
	// verify base list
	for (PwsRecord rec : li1.toList()) {
		assertFalse("record not removed in removeGroup()", rec.getGroup() == grpValue);
	}
	
	// remove empty group
	int size = li1.size();
	li2 = li1.removeGroup("");
	assertTrue("mismatch in number of removed records (GROUP remove)", li2.size() == 5);
	assertTrue("mismatch in remove empty group", li1.size() == size-5);
	assertFalse(li1.containsGroup(""));
	
	// remove null group
	li2 = li1.removeGroup("");
	assertTrue("false: records removed with null group parameter", li2.size() == 0);
}

/**
 * Test list instantiation with and without preset content (all constructors). 
 * Test creation + uniqueness of multiple list UUIDs. 
 * @throws DuplicateEntryException 
 */
@Test
public void test_init () throws DuplicateEntryException {
	
	PwsRecordList li1, li2, li3;
	
	// plain empty list
	li1 = new PwsRecordList();
	test_state(li1, 0, false, true, null, "init1");
	
	// lists with preset content
	Collection<PwsRecord> col = getRecordCollection(3);
	li2 = new PwsRecordList(col);
	test_state(li2, 3, false, true, null, "init2");
	assertNotEquals("", li1.getUUID(), li2.getUUID());
	
	PwsRecord[] recArr = col.toArray(new PwsRecord[0]);
	li2 = new PwsRecordList(recArr);
	test_state(li2, 3, false, true, null, "init3");
	assertNotEquals("UUID not unique", li1.getUUID(), li2.getUUID());
	
	DefaultRecordWrapper wrps[] = DefaultRecordWrapper.makeWrappers(recArr, null);
	li3 = new PwsRecordList(wrps);
	test_state(li3, 3, false, true, null, "init4");
	assertNotEquals("UUID not unique", li3.getUUID(), li1.getUUID());
	assertNotEquals("UUID not unique", li3.getUUID(), li2.getUUID());

	// presetting constructors with null parameter (allowed)
	li1 = new PwsRecordList((Collection<PwsRecord>)null);
	test_state(li1, 0, false, true, null, "init5");
	
	li2 = new PwsRecordList((PwsRecord[])null);
	test_state(li2, 0, false, true, null, "init6");
	assertNotEquals("UUID not unique", li1.getUUID(), li2.getUUID());
	
	li3 = new PwsRecordList((DefaultRecordWrapper[])null);
	test_state(li3, 0, false, true, null, "init7");
	assertNotEquals("UUID not unique", li2.getUUID(), li3.getUUID());
}

/** Tests the contains(PwsRecord), contains(UUID) and clear() methods.
 * @throws DuplicateEntryException 
 */
@Test
public void test_contains_clear () throws DuplicateEntryException {
	Collection<PwsRecord> col1, col2;
	PwsRecordList li1;
	
	col1 = getRecordCollection(3);
	col2 = getRecordCollection(3);
	li1 = new PwsRecordList(col1);
	
	// test all col1 elements are contained
	for ( PwsRecord rec : col1 ) {
		UUID uuid = rec.getRecordID();
		assertTrue("contains() error: does not report element contained (record): " + uuid,
				li1.contains(rec));
		assertTrue("contains() error: does not report element contained (UUID): " + uuid,
				li1.contains(uuid));
	}
	
	// test no col2 element is contained
	for ( PwsRecord rec : col2 ) {
		UUID uuid = rec.getRecordID();
		assertFalse("contains() error: does falsely report element contained (record): " + uuid,
				li1.contains(rec));
		assertFalse("contains() error: does falsely report element contained (UUID): " + uuid,
				li1.contains(uuid));
	}
	
	// test no col1 element is contained after CLEAR
	li1.resetModified();
	li1.clear();
	test_state(li1, 0, true, false, null, "clear");
	for ( PwsRecord rec : col1 ) {
		UUID uuid = rec.getRecordID();
		assertFalse("contains() error: does falsely report element contained (record) - after clear: " + uuid,
				li1.contains(rec));
		assertFalse("contains() error: does falsely report element contained (UUID) - after clear: " + uuid,
				li1.contains(uuid));
	}
}

/** Tests the clone() method and that a clone works equivalent to a deep clone.
 */
@Test
public void test_clone () throws DuplicateEntryException, NoSuchRecordException {
	Collection<PwsRecord> col1, col2;
	PwsRecordList li1, li2;
	byte[] sig1;
	
	col1 = getRecordCollection(30);
	li1 = new PwsRecordList(col1);
	sig1 = li1.getSignature();
	
	li2 = (PwsRecordList)li1.clone();
	test_state(li2, col1.size(), false, true, sig1, "test clone 1");
	col2 = li2.toList();

	assertEquals("clone has different UUID", li1.getUUID(), li2.getUUID());
	assertTrue("clone not successful, 1", li2.containsCollection(col1));
	assertTrue("clone not successful, 2", li1.containsCollection(col2));
	assertFalse("clone should have different instance-ID", li1.getInstId() == li2.getInstId());
	
	// clone keeps the modified marker and loses file listeners
	li1.addFileListener( testFileListener );
	li1.addRecord(createRecord(1));
	li2 = (PwsRecordList)li1.clone();
	test_state(li2, col1.size()+1, true, true, null, "test clone 2");
	assertNull("clone should have no file listeners", li2.getFileListeners());
	
	// probe if clone works as deep clone (though it is not)
	li1 = new PwsRecordList();
	PwsRecord rec = createRecord(0);
	li1.addRecord(rec);
	String testValue = "AhlSihlkhd7Zp";
	li2 = (PwsRecordList)li1.clone();
	
	// modify list 1
	rec.setTitle(testValue);
	li1.updateRecord(rec);
	
	// recall value from list 2 (may not be identical)
	rec = li2.getRecord(rec.getRecordID());
	assertNotEquals("clone is not a shallow copy", testValue, rec.getTitle());
}

/** Tests the copy() method.
 */
@Test
public void test_copy () throws DuplicateEntryException, NoSuchRecordException {
	Collection<PwsRecord> col1, col2;
	PwsRecordList li1, li2;
	byte[] sig1;
	
	col1 = getRecordCollection(30);
	li1 = new PwsRecordList(col1);
	sig1 = li1.getSignature();
	
	li2 = li1.copy();
	test_state(li2, col1.size(), false, true, sig1, "test copy 1");
	col2 = li2.toList();

	assertNotEquals("copy has identical UUID", li1.getUUID(), li2.getUUID());
	assertTrue("copy not successful, 1", li2.containsCollection(col1));
	assertTrue("copy not successful, 2", li1.containsCollection(col2));
	assertFalse("copy should have different instance-ID", li1.getInstId() == li2.getInstId());
	
	// copy keeps the modified marker and loses file listeners
	li1.addFileListener( testFileListener );
	li1.addRecord(createRecord(1));
	li2 = (PwsRecordList)li1.clone();
	test_state(li2, col1.size()+1, true, true, null, "test copy 2");
	assertNull("copy should have no file listeners", li2.getFileListeners());
	
	// probe if copy works as deep clone (though it is not)
	li1 = new PwsRecordList();
	PwsRecord rec = createRecord(0);
	li1.addRecord(rec);
	String testValue = "AhlSihlkhd7Zp";
	li2 = (PwsRecordList)li1.clone();
	
	// modify list 1
	rec.setTitle(testValue);
	li1.updateRecord(rec);
	
	// recall value from list 2 (may not be identical)
	rec = li2.getRecord(rec.getRecordID());
	assertNotEquals("clone is not a shallow copy", testValue, rec.getTitle());
}

/** Tests the containsCollection() method.
 */
@Test
public void test_contains_collection () throws DuplicateEntryException {
	Collection<PwsRecord> col1, col2, col3, emptyCol;
	PwsRecordList li1, li2;

	col1 = getRecordCollection(6);
	col2 = getRecordCollection(6);
	li1 = new PwsRecordList(col1);
	emptyCol = new ArrayList<PwsRecord>();

	assertTrue("does not contain initial collection", li1.containsCollection(col1));
	assertTrue("does not contain empty collection",	li1.containsCollection(emptyCol));
	assertFalse("falsely contains alien collection", li1.containsCollection(col2));
	assertFalse("falsely contains null collection", li1.containsCollection(null));

	// extension of record list does not change containment
	li1.addRecord(createRecord(0));
	assertTrue("does not contain initial collection after list extension", li1.containsCollection(col1));

	// reduction of record list prevents containment
	PwsRecord rec = col1.iterator().next();
	li2 = (PwsRecordList)li1.clone();
	li2.removeRecord(rec);
	assertFalse("falsely contains initial collection after list reduction", li2.containsCollection(col1));

	// contains reduced collection
	col3 = new ArrayList<PwsRecord>(col1);
	col3.remove(rec);
	assertTrue("does not contain reduced initial collection", li1.containsCollection(col3));

	// does not contain extended collection
	col3 = new ArrayList<PwsRecord>(col1);
	col3.add(createRecord(1));
	assertFalse("falsely contains extended initial collection", li1.containsCollection(col3));
	
	// adding an alien collection leads to its containment
	li1.addCollection(col2);
	assertTrue("should contain added alien collection", li1.containsCollection(col2));
	col3 = new ArrayList<PwsRecord>(col1);
	col3.addAll(col2);
	assertTrue("should contain union collection", li1.containsCollection(col3));
	
}

/** Tests the containsRecordList() method.
 */
@Test
public void test_contains_recordlist () throws DuplicateEntryException {
	Collection<PwsRecord> col1, col2;
	PwsRecordList li1, li1Org, li2, li2Org, emptyLi;

	col1 = getRecordCollection(6);
	col2 = getRecordCollection(6);
	li1 = new PwsRecordList(col1);
	li1Org = li1.copy();
	li2 = new PwsRecordList(col2);
	li2Org = li2.copy();
	emptyLi = new PwsRecordList();

	assertTrue("does not contain itself", li1.containsRecordList(li1));
	assertTrue("does not contain copy of itself", li1.containsRecordList(li1Org));
	assertTrue("does not contain empty list",	li1.containsRecordList(emptyLi));
	assertFalse("falsely contains alien list", li1.containsRecordList(li2));
	assertFalse("falsely contains null list", li1.containsRecordList(null));

	// extension of record list does not change containment
	li1.addRecord(createRecord(0));
	assertTrue("does not contain initial collection after list extension", li1.containsRecordList(li1Org));

	// reduction of record list prevents containment
	PwsRecord rec = col1.iterator().next();
	li2 = (PwsRecordList)li1.clone();
	li2.removeRecord(rec);
	assertFalse("falsely contains initial collection after list reduction", li2.containsRecordList(li1Org));

	// contains reduced collection
	assertTrue("does not contain reduced initial collection", li1.containsRecordList(li2));

	// does not contain extended collection
	li2 = (PwsRecordList)li1.clone();
	li2.addRecord(createRecord(1));
	assertFalse("falsely contains extended initial collection", li1.containsRecordList(li2));
	
	// adding an alien collection leads to its containment
	li1.addRecordList(li2Org);
	assertTrue("should contain added alien collection", li1.containsRecordList(li2Org));
	assertTrue("does not contain itself after extension", li1.containsRecordList(li1));
	
}

/** Tests methods addRecord() and addRecordValid().
 */
@Test
public void test_addRecord () throws DuplicateEntryException {
	Collection<PwsRecord> col1;
	PwsRecordList li1;
	PwsRecord rec;
	
	// test on empty list
	li1 = new PwsRecordList();
	rec = createRecord(0);
	byte[] sig = rec.getSignature();
	UUID recID = rec.getRecordID();
	li1.addRecord(rec);
	test_state(li1, 1, true, true, null, "(addRecord-1)");
	
	// probe containment and value preservation
	assertTrue("list does not contain record after addRecord()", li1.contains(rec));
	assertTrue("contained record has changed content", Util.equalArrays(sig, 
			li1.getRecord(recID).getSignature()));
	
	// probe exception on double entry (addRecord)
	try {
		li1.addRecord(rec);
		fail("fails to throw exception on double entry of record");
	} catch( DuplicateEntryException e) {
	}
	
	// probe exception on double entry (addRecordValid)
	try {
		li1.addRecordValid(rec);
		fail("fails to throw exception on double entry of record");
	} catch( DuplicateEntryException e) {
	}
	
	// may insert invalid record
	rec = new PwsRecord();
	li1.addRecord(rec);
	test_state(li1, 2, true, false, null, "(addRecord-2)");
	
	// probe containment
	assertTrue("list does not contain record after addRecord()", li1.contains(rec));

	// probe exception on invalid entry
	try {
		li1.addRecordValid(rec);
		fail("fails to throw exception on entry of invalid record (addRecordValid)");
	} catch( IllegalArgumentException e) {
	}
	
	// probe addRecordValid
	rec = createRecord(1);
	li1.addRecordValid(rec);
	test_state(li1, 3, true, false, null, "(addRecordValid)");
	
	// probe containment
	assertTrue("list does not contain record after addRecordValid()", li1.contains(rec));

	// probe adding on preset list
	col1 = getRecordCollection(3);
	li1 = new PwsRecordList(col1);
	li1.addRecord(rec);
	test_state(li1, 4, true, true, null, "(addRecord-3)");

	// probe containment
	assertTrue("list does not contain record after addRecord()", li1.contains(rec));
}

/** Tests method addCollection().
 */
@Test
public void test_add_record_collection () throws DuplicateEntryException {
	Collection<PwsRecord> col1, col2;
	PwsRecordList li1, li2, li3;

	col1 = getRecordCollection(6);
	col2 = getRecordCollection(6);
	li1 = new PwsRecordList(col1);
	li2 = new PwsRecordList();

	// determine col2 data signature
	SHA256 sha = new SHA256(); 
	for (PwsRecord rec : col2) {
		sha.update(rec.getSignature());
	}
	byte[] sig = sha.digest();
	
	// test add to preset list
	li3 = li1.addCollection(col2);
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
	try {
		li2.addCollection(col1);
		fail("should throw DuplicateEntryException");
	} catch (Exception e) {
		assertTrue("false exception, expected DuplicateEntryException",
				e instanceof DuplicateEntryException);
		test_state(li2, col1.size(), false, true, null, "duplicate 1");
	}
	
	// test duplicate in parameter list
	col2 = getDuplicateCollection(5,2);
	try {
		li2.addCollection(col2);
		fail("should throw DuplicateEntryException");
	} catch (Exception e) {
		assertTrue("false exception, expected DuplicateEntryException",
				e instanceof DuplicateEntryException);
		test_state(li2, col1.size()+3, true, true, null, "duplicate 2");
	}
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

/** Tests method addRecordList().
 */
@Test
public void test_add_record_list () throws DuplicateEntryException {
	Collection<PwsRecord> col1, col2;
	PwsRecordList li1, li2, li3;
	PwsRecord rec;

	col1 = getRecordCollection(6);
	col2 = getRecordCollection(6);
	li1 = new PwsRecordList(col1);
	li2 = new PwsRecordList(col2);

	// test add to preset list
	li3 = li1.addRecordList(li2);
	test_state(li1, col1.size()+col2.size(), true, true, null, "add list 1");
	assertTrue("fails to contain added record-list", li1.containsCollection(col2));
	assertTrue("fails to contain preset record-list", li1.containsCollection(col1));
	assertTrue("should return parameter record list", li3 == li1);
	
	// test add to empty list
	li1 = new PwsRecordList(col1);
	li2 = new PwsRecordList();
	li2.addRecordList(li1);
	test_state(li2, col1.size(), true, true, null, "add list 2");
	assertTrue("fails to contain added collection", li2.containsCollection(col1));
	assertFalse("falsely contains alien collection", li2.containsCollection(col2));
	
	// test null parameter
	li2.resetModified();
	li2.addRecordList(null);
	test_state(li2, col1.size(), false, true, null, "add null col");

	// test exception on duplicates
	try {
		li2.addRecordList(li1);
		fail("should throw DuplicateEntryException");
	} catch (Exception e) {
		assertTrue("false exception, expected DuplicateEntryException",
				e instanceof DuplicateEntryException);
		test_state(li2, col1.size(), false, true, null, "duplicate 1");
	}
}

@Test
public void test_removeRecord () throws DuplicateEntryException {
	Collection<PwsRecord> col1, col2;
	PwsRecordList li1, li2;
	PwsRecord rec;
	
	// test on empty list
	col1 = getRecordCollection(15);
	li1 = new PwsRecordList(col1);
	int size = col1.size();
	test_state(li1, size, false, true, null, "initial collection");

	// probe sequential remove
	int count = 0;
	for ( PwsRecord rec1 : col1 ) {
		// remove next record 
		rec = li1.removeRecord(rec1);
		assertEquals("removed record is not matching parameter", rec1, rec);
		count++;
		test_state(li1, size-count, true, true, null, "removeRecord "+(count-1));
		
		// probe containment
		assertFalse("record still contained after removeRecord()", li1.contains(rec1));
		li1.resetModified();
	}
	
	// probe reverse sequential remove
	li1 = new PwsRecordList(col1);
	Collections.reverse((List<PwsRecord>)col1);
	count = 0;
	for ( PwsRecord rec1 : col1 ) {
		// remove next record 
		li1.removeRecord(rec1); 
		count++;
		test_state(li1, size-count, true, true, null, "removeRecord-rv "+(count-1));
		
		// probe containment
		assertFalse("record still contained after removeRecord()", li1.contains(rec1));
		li1.resetModified();
	}
	
	// probe random remove
	col2 = getRecordCollection(30);
	List<PwsRecord> list = (List<PwsRecord>)col2;
	li1 = new PwsRecordList(col2);
	size = col2.size();
	count = 0;
	for ( int i = 0; i < size; i++ ) {
		// get random selection
		int sel = Util.nextRand(list.size());
		
		// remove next record 
		PwsRecord rec1 = list.remove(sel);
		li1.removeRecord(rec1); 
		count++;
		test_state(li1, size-count, true, true, null, "removeRecord-rnd "+(count-1));
		
		// probe containment
		assertFalse("record still contained after removeRecord()", li1.contains(rec1));
		li1.resetModified();
	}
	
	// probe failed remove is harmless to record list
	col1 = getRecordCollection(15);
	li1 = new PwsRecordList(col1);
	rec = createRecord(0);
	
	li2 = (PwsRecordList)li1.clone();
	assertNull("removal of non-contained record!", li1.removeRecord(rec));
	assertTrue("failing removeRecord() loses a list element", li1.containsRecordList(li2));
	
	// probe equivalence of remove record and UUID
	int index = Util.nextRand(15);
	rec = ((List<PwsRecord>)col1).get(index);
	li1.removeRecord(rec);
	li2.removeRecord(rec.getRecordID());
	assertTrue("remove record and remove UUID are not working same", 
			Util.equalArrays(li1.getSignature(), li2.getSignature()));
}

/** Tests method removeCollection().
 */
@Test
public void test_remove_record_collection () throws DuplicateEntryException {
	Collection<PwsRecord> col1, col2, col3;
	PwsRecordList li1;
	List<PwsRecord> rl1;

	col1 = getRecordCollection(5);
	col2 = getRecordCollection(8);
	col3 = getRecordCollection(0);
	col3.addAll(col1);
	col3.addAll(col2);
	
	// probe remove of contained set
	li1 = new PwsRecordList(col3);
	test_state(li1, col1.size()+col2.size(), false, true, null, "remove coll 1");
	rl1 = li1.removeCollection(col1);
	test_state(li1, col2.size(), true, true, null, "remove coll 2");
	assertTrue("should contain remainder collection after remove", li1.containsCollection(col2));
	assertFalse("falsely contains removed collection", li1.containsCollection(col1));
	assertNull("return list should be null", rl1);
	
	// probe remove of not contained set
	rl1 = li1.removeCollection(col1);
	test_state(li1, col2.size(), true, true, null, "remove coll 2");
	assertTrue("should contain remainder collection after remove", li1.containsCollection(col2));
	assertFalse("falsely contains removed collection", li1.containsCollection(col1));
	assertTrue("return list should be parameter list", sameContentColls(rl1, col1));
	
	// probe remove of empty set
	rl1 = li1.removeCollection(getRecordCollection(0));
	test_state(li1, col2.size(), true, true, null, "remove coll 3");
	assertTrue("should contain remainder collection", li1.containsCollection(col2));
	assertNull("return list should be null", rl1);
	
	// probe remove of null set
	rl1 = li1.removeCollection(null);
	test_state(li1, col2.size(), true, true, null, "remove coll 4");
	assertTrue("should contain remainder", li1.containsCollection(col2));
	assertNull("return list should be null", rl1);
	
	// probe remove of part-contained set
	rl1 = li1.removeCollection(col3);
	test_state(li1, 0, true, true, null, "remove coll 5");
	assertFalse("falsely contains removed collection", li1.containsCollection(col1));
	assertFalse("falsely contains removed collection", li1.containsCollection(col2));
	assertTrue("return list failure", sameContentColls(rl1, col1));
}

/** Tests method removeCollection().
 */
@Test
public void test_remove_record_list () throws DuplicateEntryException {
	Collection<PwsRecord> col1, col2, col3;
	PwsRecordList li1, li2, li3, rl1, emptyLi;

	col1 = getRecordCollection(5);
	col2 = getRecordCollection(8);
	col3 = getRecordCollection(0);
	col3.addAll(col1);
	col3.addAll(col2);
	li1 = new PwsRecordList(col3);
	li2 = new PwsRecordList(col1);
	emptyLi = new PwsRecordList();
	
	// probe remove of contained set
	rl1 = li1.removeRecordList(li2);
	test_state(li1, col2.size(), true, true, null, "remove list 1");
	assertTrue("should contain remainder list after remove", li1.containsCollection(col2));
	assertFalse("falsely contains removed list", li1.containsCollection(col1));
	assertNull("return list should be null", rl1);
	
	// probe remove of not contained set
	rl1 = li1.removeRecordList(li2);
	test_state(li1, col2.size(), true, true, null, "remove list 2");
	assertTrue("should contain remainder list after remove", li1.containsCollection(col2));
	assertFalse("falsely contains removed list", li1.containsCollection(col1));
	assertTrue("return list should be parameter list", sameContentLists(rl1, li2));
	
	// probe remove of empty set
	rl1 = li1.removeRecordList(emptyLi);
	test_state(li1, col2.size(), true, true, null, "remove list 3");
	assertTrue("should contain remainder list", li1.containsCollection(col2));
	assertNull("return list should be null", rl1);
	
	// probe remove of null set
	rl1 = li1.removeRecordList(null);
	test_state(li1, col2.size(), true, true, null, "remove list 4");
	assertTrue("should contain remainder", li1.containsCollection(col2));
	assertNull("return list should be null", rl1);
	
	// probe remove of part-contained set
	li3 = new PwsRecordList(col3);
	rl1 = li1.removeRecordList(li3);
	test_state(li1, 0, true, true, null, "remove coll 5");
	assertFalse("falsely contains removed list", li1.containsCollection(col1));
	assertFalse("falsely contains removed list", li1.containsCollection(col2));
	assertTrue("return list failure", sameContentLists(rl1, li2));
}

/** Tests methods updateRecord() and updateRecordValid().
 * @throws DuplicateEntryException 
 */
@Test
public void test_update_record () throws NoSuchRecordException, DuplicateEntryException {
	AllMethods_RecordList li1;
	Collection<PwsRecord> col1;
	PwsRecord rec, rec2, listRec1, listRec2;
	UUID id1, id2;
	byte[] sig1;

	col1 = getRecordCollection(8);
	li1 = new AllMethods_RecordList(col1);

	// pick record
	rec = col1.iterator().next();
	id1 = rec.getRecordID();
	sig1 = rec.getSignature();
	
	// test correctness of getRecord
	rec = li1.getRecord(id1);
	assertEquals("getRecord failure", id1, rec.getRecordID());
	assertTrue("getRecord signature failure", Util.equalArrays(sig1, rec.getSignature()));

	// test correctness of update
	rec.setTitle("new value for record title");
	sig1 = rec.getSignature();
	listRec1 = li1.getRecordShallow(id1);
	li1.updateRecord(rec);
	
	listRec2 = li1.getRecordShallow(id1);
	assertFalse("list record does not change", listRec1 == listRec2);
	assertTrue("updated record data error", Util.equalArrays(sig1, listRec2.getSignature()));
	rec2 = li1.getRecord(id1);
	assertFalse("rendered list record does not change", rec2 == rec);
	assertFalse("rendered list record is not a clone", rec2 == listRec2);
	assertTrue("updated record data error", Util.equalArrays(sig1, rec2.getSignature()));
	
	// test update invalid record
	rec.setTitle(null);
	assertFalse(rec.isValid());
	li1.updateRecord(rec);
	assertTrue("update of invalid record failed", li1.countInvalid() == 1);

	// test update record valid
	try {
		li1.updateRecordValid(rec);
		fail("exception expected at update invalid record");
	} catch (Exception e) {
		assertTrue("false exception thrown", e instanceof IllegalArgumentException);
	}
	
	// test update not-contained record
	try {
		rec = createRecord(0);
		li1.updateRecord(rec);
		fail("no exception thrown on false update record");
	} catch (Exception e) {
		assertTrue("false exception", e instanceof NoSuchRecordException);
	}

	// test update null record
	try {
		li1.updateRecord(null);
		fail("no exception thrown on null parameter");
	} catch (Exception e) {
		assertTrue("false exception", e instanceof NullPointerException);
	}
}

/** Tests method updateCollection():
 */
@Test
public void test_update_collection () throws DuplicateEntryException {
	AllMethods_RecordList li1;
	Collection<PwsRecord> col1, col2, col3;
	PwsRecord rec, rec2, listRec1, listRec2;
	List<PwsRecord> resLi1, resLi2;
	UUID id1, id2;
	byte[] sig1;

	col1 = getRecordCollection(8);
	col2 = getRecordCollection(8);
	li1 = new AllMethods_RecordList(col1);
	li1.addCollection(col2);

	// modify records of col2 + store signatures in list
	List<byte[]> sigList = new ArrayList<byte[]>();
	for (PwsRecord r : col2) {
		r.setEmail("kannitscheider.hans@gmail.de");
		sigList.add(r.getSignature());
	}

	resLi1 = li1.updateCollection(col2);
	assertNull("result list should be null", resLi1);
	
	// probe updates
	Iterator<byte[]> it = sigList.iterator();
	for (PwsRecord r : col2) {
		rec = li1.getRecordShallow(r.getRecordID());
		assertFalse("updates are not buffered", rec == r);
		assertFalse("getRecord is not buffered", rec == li1.getRecord(r));
		assertTrue("updates are not correct", Util.equalArrays(
				it.next(), rec.getSignature()));
	}
	
	// probe can iterate updates
	resLi1 = li1.updateCollection(col2);
	assertNull("result list should be null (iterated update)", resLi1);
	
	// probe result list
	int size = 8;
	col3 = getRecordCollection(size);
	col3.addAll(col1);
	resLi1 = li1.updateCollection(col3);
	assertNotNull("result list should not be null", resLi1);
	assertTrue("result list size mismatch", resLi1.size() == size);
	resLi2 = new ArrayList<PwsRecord>();
	for (PwsRecord r : resLi1) {
		assertTrue("result list element not commanded", col3.contains(r));
		assertFalse("result list element duplicate", resLi2.contains(r));
		resLi2.add(r);
	}
	
	// probe update empty list
	sig1 = li1.getSignature();
	resLi1 = li1.updateCollection(new ArrayList<PwsRecord>());
	assertNull("result list should be null (empty parameter)", resLi1);
	assertTrue("false list modification", Util.equalArrays(sig1, li1.getSignature()));
	
	// probe update null list
	resLi1 = li1.updateCollection(null);
	assertNull("result list should be null (empty parameter)", resLi1);
	assertTrue("false list modification", Util.equalArrays(sig1, li1.getSignature()));
}

/** Tests method updateCollection():
 */
@Test
public void test_update_record_list () throws DuplicateEntryException {
	AllMethods_RecordList li1;
	PwsRecordList li2, li3;
	Collection<PwsRecord> col1, col2, col3;
	PwsRecord rec, rec2, listRec1, listRec2;
	PwsRecordList resLi1;
	UUID id1, id2;
	byte[] sig1;

	col1 = getRecordCollection(8);
	col2 = getRecordCollection(8);
	li1 = new AllMethods_RecordList(col1);
	li1.addCollection(col2);

	// modify records of col2 + store signatures in list
	List<byte[]> sigList = new ArrayList<byte[]>();
	for (PwsRecord r : col2) {
		r.setEmail("kannitscheider.hans@gmail.de");
		sigList.add(r.getSignature());
	}
	li2 = new PwsRecordList(col2);

	resLi1 = li1.updateRecordList(li2);
	assertNull("result list should be null", resLi1);
	
	// probe updates
	Iterator<byte[]> it = sigList.iterator();
	for (PwsRecord r : col2) {
		rec = li1.getRecordShallow(r.getRecordID());
		assertFalse("updates are not buffered", rec == r);
		assertFalse("getRecord is not buffered", rec == li1.getRecord(r));
		assertTrue("updates are not correct", Util.equalArrays(
				it.next(), rec.getSignature()));
	}
	
	// probe can iterate updates
	resLi1 = li1.updateRecordList(li2);
	assertNull("result list should be null (iterated update)", resLi1);
	
	// probe result list
	int size = 8;
	col3 = getRecordCollection(size);
	col3.addAll(col1);
	li3 = new PwsRecordList(col3);
	resLi1 = li1.updateRecordList(li3);
	assertNotNull("result list should not be null", resLi1);
	assertTrue("result list size mismatch", resLi1.getRecordCount() == size);
	List<PwsRecord> recLi = new ArrayList<PwsRecord>();
	for (PwsRecord r : resLi1.toArray()) {
		assertTrue("result list element not commanded", col3.contains(r));
		assertFalse("result list element duplicate", recLi.contains(r));
		recLi.add(r);
	}
	
	// probe update empty list
	sig1 = li1.getSignature();
	resLi1 = li1.updateRecordList(new PwsRecordList());
	assertNull("result list should be null (empty parameter)", resLi1);
	assertTrue("false list modification", Util.equalArrays(sig1, li1.getSignature()));
	
	// probe update null list
	resLi1 = li1.updateRecordList((PwsRecordList)null);
	assertNull("result list should be null (empty parameter)", resLi1);
	assertTrue("false list modification", Util.equalArrays(sig1, li1.getSignature()));
}

@Test
public void test_set_operations () throws DuplicateEntryException {
	Collection<PwsRecord> col1, col2, col3;
	PwsRecordList li1, li2, li3, li4, li5;
	byte[] sig1, sig2, sig4;
	int size;

	col1 = getRecordCollection(6);
	col2 = getRecordCollection(6);
	col3 = getRecordCollection(6);
	li1 = new PwsRecordList(col1);
	li2 = new PwsRecordList(col2);
	li3 = new PwsRecordList(col3);
	sig1 = li1.getSignature();
	sig2 = li2.getSignature();

	// test cutset of alien lists is empty
	li4 = li1.intersectionRecordList(li2);
	test_state(li4, 0, false, false, null, "cutset alien empty");
	assertNotEquals(li1, li4);
	assertTrue("signature failure after cutset", Util.equalArrays(sig1, li1.getSignature()));
	assertTrue("signature failure after cutset", Util.equalArrays(sig2, li2.getSignature()));
	
	// test cutset with null list is empty
	li4 = li1.intersectionRecordList(null);
	test_state(li4, 0, false, false, null, "cutset null empty");
	assertNotEquals(li1, li4);
	assertTrue("signature failure after cutset", Util.equalArrays(sig1, li1.getSignature()));
	
	// test cutset with empty list is empty
	li4 = li1.intersectionRecordList(new PwsRecordList());
	test_state(li4, 0, false, false, null, "cutset empty empty");
	assertNotEquals(li1, li4);
	assertTrue("signature failure after cutset", Util.equalArrays(sig1, li1.getSignature()));
	
	// test cutset with self is self
	size = li1.size();
	li4 = li1.intersectionRecordList(li1);
	test_state(li4, size, false, true, sig1, "cutset self");
	assertNotEquals(li1, li4);
	assertTrue("should have list identity after cutset with self", 
	        sameContentLists(li1, li4));
	
	// test union of alien lists
	li4 = li1.unionRecordList(li2).unionRecordList(li3);
	size = col1.size() + col2.size() + col3.size();
	test_state(li4, size, false, true, null, "unionset full");
	assertTrue("union contains constituent list", li4.containsRecordList(li1));
	assertTrue("union contains constituent list", li4.containsRecordList(li2));
	assertTrue("union contains constituent list", li4.containsRecordList(li3));
	sig4 = li4.getSignature();

	// test cutset with union
	size = li2.size();
	li5 = li4.intersectionRecordList(li2);
	test_state(li5, size, false, true, sig2, "cutset li2");
	assertTrue("should have original list after cutset with union", 
			sameContentLists(li2, li5));
	
	// test union with null list is self
	size = li1.size();
	li5 = li1.unionRecordList(null);
	test_state(li5, size, false, true, sig1, "union null self");
	assertNotEquals(li1, li5);
	
	// test union with empty list is self
	li5 = li1.unionRecordList(new PwsRecordList());
	test_state(li5, size, false, true, sig1, "union empty self");
	assertNotEquals(li1, li5);
	
	// test union with empty list is self
	li5 = li1.unionRecordList(li1);
	test_state(li5, size, false, true, sig1, "union self self");
	assertNotEquals(li1, li5);
	
	// test exclude list
	li5 = li4.excludeRecordList(li1);
	size = col1.size() + col2.size() + col3.size();
	test_state(li4, size, false, true, sig4, "unionset after exclude");
	assertNotEquals(li4, li5);
	size = col2.size() + col3.size();
	test_state(li5, size, false, true, null, "exclude list");
	assertTrue("does not contain constituent list", li5.containsRecordList(li2));
	assertTrue("does not contain constituent list", li5.containsRecordList(li3));
	assertFalse("falsely contains excluded list", li5.containsRecordList(li1));
	
	// test exclude with null list is self
	size = li1.size();
	li5 = li1.excludeRecordList(null);
	test_state(li5, size, false, true, sig1, "exclude null self");
	assertNotEquals(li1, li5);
	
	// test exclude with empty list is self
	li5 = li1.excludeRecordList(new PwsRecordList());
	test_state(li5, size, false, true, sig1, "exclude empty self");
	assertNotEquals(li1, li5);
	
	// test exclude self list is empty
	size = li1.size();
	li5 = li1.excludeRecordList(li1);
	test_state(li5, 0, false, true, null, "exclude self empty");
	test_state(li1, size, false, true, sig1, "exclude self");
	assertNotEquals(li1, li5);
	
}

/** Tests methods toArray(), toList() and toRecordWrappers().
 * @throws DuplicateEntryException 
 */
@Test
public void test_to_relations () throws DuplicateEntryException {
	Collection<PwsRecord> col1;
	AllMethods_RecordList li1;

	col1 = getRecordCollection(6);
	li1 = new AllMethods_RecordList(col1);


	// test to-array
	PwsRecord[] arr = li1.toArray();
	assertTrue("rendered record array size not equal", arr.length == li1.size());
	for ( PwsRecord rec : arr ) {
		PwsRecord listRec = li1.getRecordShallow(rec.getRecordID());
		assertNotNull("list does not contain rendered array record", listRec);
		assertFalse("rendered array record should be clone", rec == listRec);
		assertEquals("rendered array record should be equal to list record", rec, listRec);
		assertTrue("rendered array record content failure", Util.equalArrays(
				rec.getSignature(), listRec.getSignature()));
	}
	
	// test to-list
	List<PwsRecord> list = li1.toList();
	assertTrue("rendered record list size not equal", list.size() == li1.size());
	for ( PwsRecord rec : list ) {
		PwsRecord listRec = li1.getRecordShallow(rec.getRecordID());
		assertNotNull("list does not contain rendered list record", listRec);
		assertFalse("rendered list record should be clone", rec == listRec);
		assertEquals("rendered list record should be equal to list record", rec, listRec);
		assertTrue("rendered list record content failure", Util.equalArrays(
				rec.getSignature(), listRec.getSignature()));
	}
	
	// test to-record-wrappers
	DefaultRecordWrapper[] wraps = li1.toRecordWrappers(null);
	assertTrue("rendered record wrappers size not equal", wraps.length == li1.size());
	for ( DefaultRecordWrapper wrp : wraps ) {
		PwsRecord rec = wrp.getRecord();
		PwsRecord listRec = li1.getRecordShallow(rec.getRecordID());
		assertNotNull("list does not contain rendered wrapper record", listRec);
		assertFalse("rendered wrapper record should be clone", rec == listRec);
		assertEquals("rendered wrapper record should be equal to list record", rec, listRec);
		assertTrue("rendered wrapper record content failure", Util.equalArrays(
				rec.getSignature(), listRec.getSignature()));
	}
}

@Test
public void test_settings () throws DuplicateEntryException {
	AllMethods_RecordList li1;
	
	li1 = new AllMethods_RecordList();

	// test size, getRecordCount, isEmpty, isModified, hasInvalidRecs
	assertTrue("size + getRecordCount not equal, 1", li1.size() == li1.getRecordCount());
	assertFalse("isModified should not be true initial", li1.isModified());
	assertTrue("isEmpty should be true initial", li1.isEmpty());
	assertFalse("hasInvalidRecs should not be true initial", li1.hasInvalidRecs());

	li1.addRecord(createRecord(0));
	assertTrue("size + getRecordCount not equal, 1", li1.size() == li1.getRecordCount());
	assertTrue("isModified should be true after insert", li1.isModified());
	assertFalse("isEmpty should not be true after insert", li1.isEmpty());
	assertFalse("hasInvalidRecs should not be true after insert", li1.hasInvalidRecs());
	
	// test reset modified
	li1.resetModified();
	assertFalse("isModified should not be true after resetModified", li1.isModified());
	li1.setModified();
	assertTrue("isModified should be true after setModified", li1.isModified());
	li1.resetModified();
	
	// insert invalid record
	PwsRecord rec = createRecord(1);
	rec.setTitle(null);
	rec.setPassword(null);
	assertFalse(rec.isValid());
	li1.addRecord(rec);
	assertTrue("size + getRecordCount not equal, 1", li1.size() == li1.getRecordCount());
	assertTrue("isModified should be true after insert", li1.isModified());
	assertFalse("isEmpty should not be true after insert", li1.isEmpty());
	assertTrue("hasInvalidRecs should be true after insert invalid rec", li1.hasInvalidRecs());
	
	// test setUUID
	UUID id1 = li1.getUUID();
	UUID id2 = new UUID();
	li1.setUUID(id2);
	assertNotEquals("control values of UUID", id1, id2);
	assertEquals("cannot set list UUID", li1.getUUID(), id2);

	
}

/** This tests methods hasInvalidRecs(), countInvalid() and clearInvalidRecs().
 */
@Test
public void test_invalid_recs () throws DuplicateEntryException {
	List<PwsRecord> col1, col2;
	PwsRecordList li1, li2, li3, li4, li5;
	PwsRecord rec1, rec2;
	byte[] sig1, sig2, sig4;

	int size = 6;
	col1 = (List<PwsRecord>)getRecordCollection(size);
	li1 = new PwsRecordList(col1);
	sig1 = li1.getSignature();

	// create list with invalids
	rec1 = col1.get(3);
	rec1.setTitle(null);
	rec2 = col1.get(4);
	rec2.setTitle(null);
	col2 = li1.updateCollection(col1);
	assertNull("updateCollection returns false list", col2);
	
	// test counter 
	assertTrue("false invalid counter value", li1.countInvalid() == 2);
	assertTrue("false hasInvalidRecs value", li1.hasInvalidRecs());
	
	// test deletion
	li2 = li1.clearInvalidRecs();
	assertTrue("false invalid counter after clearing", li1.countInvalid() == 0);
	assertFalse("false hasInvalidRecs value", li1.hasInvalidRecs());
	assertTrue("bad return list size", li2.size() == 2);
	assertTrue(li2.contains(rec1));
	assertTrue(li2.contains(rec2));
}

/** This tests method countExpired().
 */
@Test
public void test_expired_recs () throws DuplicateEntryException {
	List<PwsRecord> col1, col2;
	PwsRecordList li1, li2, li3, li4, li5;
	PwsRecord rec1, rec2;
	byte[] sig1, sig2, sig4;

	int size = 6;
	col1 = (List<PwsRecord>)getRecordCollection(size);
	li1 = new PwsRecordList(col1);
	sig1 = li1.getSignature();

	// create list with invalids
	rec1 = col1.get(3);
	rec1.setPassLifeTime(5000);
	rec2 = col1.get(4);
	rec2.setPassLifeTime(5000);
	col2 = li1.updateCollection(col1);
	assertNull("updateCollection returns list", col2);
	assertFalse("hasInvalidRecs should be false", li1.hasInvalidRecs());
	
	// test counter 
	assertTrue("false expired counter value", li1.countExpired(5000) == 0);
	assertTrue("false expired counter value", li1.countExpired(5001) == 2);
	
	// test deletion
	rec1.setPassLifeTime(15000);
	rec2.setPassLifeTime(15000);
	li1.updateCollection(col1);
	assertTrue("false expired counter value", li1.countExpired(5001) == 0);
}

/** Tests methods iterator(), internalIterator() and getRecordShallow().
 * @throws DuplicateEntryException 
 */
@Test
public void test_iterators () throws DuplicateEntryException {
	AllMethods_RecordList li1;
	Collection<PwsRecord> col1;
	List<PwsRecord> list1, list2;
	Iterator<PwsRecord> it;
	int count;

	col1 = getRecordCollection(6);
	li1 = new AllMethods_RecordList(col1);
	list1 = new ArrayList<PwsRecord>();
	list2 = new ArrayList<PwsRecord>();

	// iterator
	count = 0;
	for ( it = li1.iterator(); it.hasNext(); ) {
		// returned record is contained
		PwsRecord rec = it.next();
		assertTrue("iterator item is not from the list", li1.contains(rec));
		
		// returned record is unique
		assertFalse("iterator item is not unique", list1.contains(rec));
		list1.add(rec);
		
		// returned record is a clone
		PwsRecord shallowItem = li1.getRecordShallow(rec.getRecordID());
		PwsRecord shallow2 = li1.getRecordShallow(rec.getRecordID());
		assertEquals("getShallowRecord item is not correct", rec, shallowItem);
		assertTrue("getShallowRecord item is not a constant", shallow2 == shallowItem);
		assertFalse("iterator item is not a clone", rec == shallowItem);
		
		// count records
		count++;
	}
	assertTrue("iterator count mismatch", count == li1.size());

	// internalIterator
	count = 0;
	for ( it = li1.internalIterator(); it.hasNext(); ) {
		// returned record is contained
		PwsRecord rec = it.next();
		assertTrue("internalIterator item is not from the list", li1.contains(rec));
		
		// returned record is unique
		assertFalse("internalIterator item is not unique", list2.contains(rec));
		list2.add(rec);
		
		// returned record is a clone
		PwsRecord shallowItem = li1.getRecordShallow(rec.getRecordID());
		assertTrue("internalIterator item should be a clone", rec == shallowItem);
		
		// count records
		count++;
	}
	assertTrue("internalIterator count mismatch", count == li1.size());
	
	// probe getRecordShallow
	assertNull(li1.getRecordShallow(null));
	assertNull(li1.getRecordShallow(createRecord(0).getRecordID()));
}

/** Tests method getSignature() and signature systematic logic.
 * @throws DuplicateEntryException 
 */
@Test
public void test_signature () throws DuplicateEntryException {
	PwsRecordList li1, li2, li3;
	Collection<PwsRecord> col1, col2;
	List<PwsRecord> list1;
	byte[] sig1, sig2, sig3;

	col1 = getRecordCollection(6);
	col2 = getRecordCollection(6);
	li1 = new PwsRecordList(col1);
	li2 = new PwsRecordList(col2);
	list1 = new ArrayList<PwsRecord>();

	// signature of empty list
	sig1 = new PwsRecordList().getSignature();
	sig2 = new PwsRecordList().getSignature();
	assertTrue("signature of empty lists should be identical", 
     			Util.equalArrays(sig1, sig2));

	// signature is meaningful
	sig1 = li1.getSignature();
	sig2 = li2.getSignature();
	assertFalse("signatures of different contents should be different", 
     			Util.equalArrays(sig1, sig2));
	li3 = new PwsRecordList(col1);
	sig3 = li3.getSignature();
	assertTrue("signatures of same content should be same", 
 			Util.equalArrays(sig1, sig3));
	
	// signature agnostic of insertion sequence
	list1 = new ArrayList<PwsRecord>(col1);
	Collections.reverse(list1);
	li3 = new PwsRecordList(list1);
	sig3 = li3.getSignature();
	assertTrue("signatures are sensible to insertion order", Util.equalArrays(sig1, sig3));
}

/** Tests methods replaceContent() and replaceFrom().
 * @throws DuplicateEntryException 
 */
@Test
public void test_replace () throws DuplicateEntryException {
	AllMethods_RecordList li1, li2;
	Collection<PwsRecord> col1, col2, col3;
	byte[] sig1, sig2, sig3;

	col1 = getRecordCollection(8);
	col2 = getRecordCollection(6);
	li1 = new AllMethods_RecordList(col1);
	li2 = new AllMethods_RecordList(col2);
	sig1 = li1.getSignature();
	sig2 = li2.getSignature();
	
	// test replaceContent with values
	UUID id1 = li1.getUUID();
	PwsRecord[] arr = li2.toArray();
	li1.replaceContent(arr);
	test_state(li1, col2.size(), true, true, null, "replace content 1");
	assertTrue("replaceContent does not place correct content", 
			Util.equalArrays(sig2, li1.getSignature()));
	assertEquals("replaceContent should not change list UUID", id1, li1.getUUID());
	PwsRecord rec = arr[0];
	assertFalse("replaceContent should add clones of records", 
			rec == li1.getRecordShallow(rec.getRecordID()));
	
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
	try {
		li1.resetModified();
		li1.replaceContent(arr);
		fail("missing exception: DuplicateEntryException");
	} catch (Exception e) {
		assertTrue("exception type failure, expected: DuplicateEntryException",
				e instanceof DuplicateEntryException);
		test_state(li1, 3, true, true, null, "replace content 4");
	}
	
	li1 = new AllMethods_RecordList(col1);
	li2 = new AllMethods_RecordList(col2);

	UUID id2 = li2.getUUID();
	li1.replaceFrom(li2);
	test_state(li1, col2.size(), true, true, null, "replace from 1");
	assertTrue("replaceFrom does not place correct content", 
			Util.equalArrays(sig2, li1.getSignature()));
	assertEquals("replaceFrom should change list UUID", id2, li1.getUUID());

	try {
		li1.replaceFrom(null);
		fail("replaceFrom should throw exception on null parameter");
	} catch (Exception e) {
		assertTrue("false exception thrown", e instanceof NullPointerException);
	}
	assertTrue("replaceFrom with null modifies content", 
			Util.equalArrays(sig2, li1.getSignature()));
}

@Test
public void test_list_events () throws DuplicateEntryException, NoSuchRecordException {
	PwsRecordList li1, li2, li3, hares;
	Collection<PwsRecord> col1, col2, col3;
	DefaultRecordWrapper[] wraps;
	List<PwsRecord> list1;
	PwsRecord rec;
	byte[] sig1, sig2, sig3;

	col1 = getRecordCollection(6);
	col2 = getRecordCollection(6);
	li1 = new PwsRecordList(col1);
	li2 = new PwsRecordList(col2);
	list1 = new ArrayList<PwsRecord>();

	Test_FileListener listener = new Test_FileListener();
	li1.addFileListener(listener);
	assertTrue("early event dispatching", listener.getCounter() == 0);
	
	// test remove one
	Iterator<PwsRecord> iterator = col1.iterator();
	rec = iterator.next();
	li1.removeRecord(rec);
	listener.testOneEvent(PwsFileEvent.RECORD_REMOVED, rec);
	
	// test add one
	rec = createRecord(1);
	listener.reset();
	li1.addRecord(rec);
	listener.testOneEvent(PwsFileEvent.RECORD_ADDED, rec);

	rec = createRecord(2);
	listener.reset();
	li1.addRecordValid(rec);
	listener.testOneEvent(PwsFileEvent.RECORD_ADDED, rec);

	// test update one identical
	rec = li1.getRecord(rec);
	listener.reset();
	li1.updateRecord(rec);
	assertTrue("no event was expected while updating unmodified record", listener.getCounter() == 0);

	// test update one modified
	rec.setTitle("new title");
	listener.reset();
	li1.updateRecord(rec);
	listener.testOneEvent(PwsFileEvent.RECORD_UPDATED, rec);
	
	rec.setTitle("Fax hat die Faxen dicke");
	listener.reset();
	li1.updateRecordValid(rec);
	listener.testOneEvent(PwsFileEvent.RECORD_UPDATED, rec);

	// test add record list + collection
	listener.reset();
	li1.addRecordList(li2);
	listener.testOneEvent(PwsFileEvent.LIST_UPDATED, null);
	
	listener.reset();
	col3 = getRecordCollection(3);
	li1.addCollection(col3);
	listener.testOneEvent(PwsFileEvent.LIST_UPDATED, null);
	
	// test various updaters
	listener.reset();
	li3 = li1.renameGroup("", "Eselsgruppe");
	Log.debug(1, "rename group, size == " + li3.size());
	listener.testOneEvent(PwsFileEvent.LIST_UPDATED, null);
	
	listener.reset();
	li3 = li1.getGroup("Stadthasen");
	wraps = li1.moveRecords(li3.toRecordWrappers(null), "Hasenkiste", false);
	Log.debug(1, "move group, size == " + wraps.length);
	listener.testOneEvent(PwsFileEvent.LIST_UPDATED, null);
	
	listener.reset();
	hares = li1.removeGroup("Hasenkiste");
	Log.debug(1, "remove group, size == " + hares.size());
	listener.testOneEvent(PwsFileEvent.LIST_UPDATED, null);
	
	listener.reset();
	col2 = getRecordCollection(3);
	li2 = new PwsRecordList(col2);
	li3 = li1.merge(li2, PwsRecordList.MERGE_INCLUDE, false)[0];
	assertTrue("incomplete merge", li3.isEmpty());
	assertTrue("merge not successful", li1.containsRecordList(li2));
	Log.debug(1, "merge list, size == " + li1.size());
	listener.testOneEvent(PwsFileEvent.LIST_UPDATED, null);
	
	// test remove record list
	
	listener.reset();
	li3 = li1.removeRecordList(li2);
	assertNull("incomplete remove list", li3);
	Log.debug(1, "remove list, size == " + li2.size());
	listener.testOneEvent(PwsFileEvent.LIST_UPDATED, null);
	
	li1.addCollection(col2);
	listener.reset();
	list1 = li1.removeCollection(col2);
	assertNull("incomplete remove collection", list1);
	Log.debug(1, "remove collection, size == " + col2.size());
	listener.testOneEvent(PwsFileEvent.LIST_UPDATED, null);
	
	// test update record list
	
	li1.addRecordList(hares);
	col3 = hares.toList();
	for (PwsRecord record : col3) {
		record.setGroup("Neue Stadt");
	}
	
	listener.reset();
	list1 = li1.updateCollection(col3);
	assertNull("incomplete collection update", list1);
	Log.debug(1, "update collection, size == " + col3.size());
	listener.testOneEvent(PwsFileEvent.LIST_UPDATED, null);

	for (PwsRecord record : col3) {
		record.setGroup("Eberhardts Scheune");
	}
	
	listener.reset();
	li2 = new PwsRecordList(col3);
	li3 = li1.updateRecordList(li2);
	assertNull("incomplete update record list", li3);
	Log.debug(1, "update record list, size == " + li2.size());
	listener.testOneEvent(PwsFileEvent.LIST_UPDATED, null);

	// test take over record list
	
	listener.reset();
	col2 = getRecordCollection(6);
	li2 = new PwsRecordList(col2);
	PwsRecord[] recs = col2.toArray(new PwsRecord[col2.size()]);
	li1.replaceContent(recs);
	assertTrue(li1.containsRecordList(li2));
	listener.testOneEvent(PwsFileEvent.LIST_UPDATED, null);
	
	listener.reset();
	col2 = getRecordCollection(6);
	li2 = new PwsRecordList(col2);
	li1.replaceFrom(li2);
	assertTrue(li1.containsRecordList(li2));
	listener.testOneEvent(PwsFileEvent.LIST_UPDATED, null);
	
	// test list cleared
	
	listener.reset();
	li3 = li1.copy();
	li3.addFileListener(listener);
	li3.clear();
	listener.testOneEvent(PwsFileEvent.LIST_CLEARED, null);

	listener.reset();
	li3 = li1.copy();
	li3.addFileListener(listener);
	li3.replaceContent(null);
	listener.testOneEvent(PwsFileEvent.LIST_CLEARED, null);

	listener.reset();
	li3 = li1.copy();
	li3.addFileListener(listener);
	li3.replaceContent(new PwsRecord[0]);
	listener.testOneEvent(PwsFileEvent.LIST_CLEARED, null);

	//  ------- NO EVENTS ------
	
	listener.reset();
	li3 = new PwsRecordList();
	li3.addFileListener(listener);
	li3.clear();
	listener.testNoEvent();
	
	li3.addCollection(getRecordCollection(0));
	listener.testNoEvent();
	
	li3.addRecordList(new PwsRecordList());
	listener.testNoEvent();
	
	li3.replaceFrom(li2);
	assertTrue(li3.size() == col2.size());
	listener.reset();
	li3.updateCollection(col2);
	listener.testNoEvent();

	li3.updateRecordList(li2);
	listener.testNoEvent();

	li3.removeCollection(getRecordCollection(0));
	listener.testNoEvent();
	
	li3.removeRecordList(new PwsRecordList());
	listener.testNoEvent();
	
	li3.merge(new PwsRecordList(), PwsRecordList.MERGE_INCLUDE, false);
	listener.testNoEvent();
	
	li3.moveRecords(new DefaultRecordWrapper[0], null, true);
	listener.testNoEvent();
	
	li3.removeGroup("Earschlitten");
	listener.testNoEvent();
	
	li3.removeRecord(new UUID());
	listener.testNoEvent();
	
	rec = li3.iterator().next();
	li3.updateRecord(rec);
	listener.testNoEvent();
}

// ---------- inner classes ----------

private class Test_FileListener implements PwsFileListener {
	private HashSet<Integer> typeSet = new HashSet<Integer>();
	private int counter;
	private PwsFileEvent event;
	
	@Override
	public void fileStateChanged(PwsFileEvent evt) {
		event = evt;
		typeSet.add(evt.getType());
		counter++;
	}

	public void reset () {
		typeSet.clear();
		counter = 0;
	}
	
	public int getCounter () {
		return counter;
	}
	
	public int getTypeCount () {
		return typeSet.size();
	}
	
	public boolean typeOccurred (int type) {
		return typeSet.contains(type);
	}
	
	public PwsFileEvent getEvent () {
		return event;
	}
	
	public void testOneEvent (int type, PwsRecord rec) {
		assertTrue("no event occurred", counter > 0);
		assertTrue("more than expected one event", counter == 1);
		assertTrue("other than expected event type", event.getType() == type);
		if (rec != null) {
			assertNotNull("event does not show record", event.getRecord());
			assertTrue("other than expected record in event", event.getRecord().equals(rec));
		} else {
			assertNull("event shows unexpected record", event.getRecord());
		}
	}
	
	public void testNoEvent () {
		assertTrue("unexpected event issued", counter == 0);
	}
}

private class AllMethods_RecordList extends PwsRecordList {

	public AllMethods_RecordList() {
		super();
	}

	public AllMethods_RecordList(Collection<PwsRecord> recs) throws DuplicateEntryException {
		super(recs);
	}

	public AllMethods_RecordList(DefaultRecordWrapper[] recs) throws DuplicateEntryException {
		super(recs);
	}

	public AllMethods_RecordList(PwsRecord[] recs) throws DuplicateEntryException {
		super(recs);
	}

	@Override
	public PwsRecord addRecordIntern(PwsRecord rec, String report)
			throws DuplicateEntryException {
		return super.addRecordIntern(rec, report);
	}

	@Override
	public Iterator<PwsRecord> internalIterator() {
		return super.internalIterator();
	}

	@Override
	public int size() {
		return super.size();
	}

	@Override
	public PwsRecord getRecordShallow(UUID recID) {
		return super.getRecordShallow(recID);
	}

	@Override
	public void setModified() {
		super.setModified();
	}

	@Override
	public void fireFileEvent(int type, PwsRecord rec) {
		super.fireFileEvent(type, rec);
	}

	@Override
	public void contentModified() {
		super.contentModified();
	}
	
	
}
}
