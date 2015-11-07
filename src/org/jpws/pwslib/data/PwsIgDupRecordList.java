/*
 *  File: PwsIgDupRecordList.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 09.2015
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

import java.util.Collection;

import org.jpws.pwslib.exception.DuplicateEntryException;
import org.jpws.pwslib.order.DefaultRecordWrapper;

/**
 * This is a subclass of {@link PwsRecordList} which does not throw 
 * <code>DuplicateEntryException</code>. The internal setting of this list
 * is to ignore the emergence of duplicates in methods where this can occur,
 * including instance constructors. 
 * <p>The behaviour of methods <code>addRecordList(), addCollection()
 *  and replaceContent()</code> is different in that these continue to operate
 *  on a parameter record list after encountering - and ignoring - duplicates.
 *
 */
public class PwsIgDupRecordList extends PwsRecordList {

	public PwsIgDupRecordList() {
	}

	public PwsIgDupRecordList(DefaultRecordWrapper[] recs) {
	   super();
       if ( recs != null && recs.length > 0 ) {
     	  PwsRecord[] arr = new PwsRecord[ recs.length ];
     	  int i = 0;
 	      for ( DefaultRecordWrapper wrp : recs ) {
 	    	 arr[i++] = wrp.getRecord(); 
 	      }
 	      replaceContent(arr);
          resetModified();
       }
	}

	public PwsIgDupRecordList(PwsRecord[] recs) {
		super();
        if ( recs != null ) {
		  replaceContent(recs);
          resetModified();
        }
	}

	public PwsIgDupRecordList(Collection<PwsRecord> recs) {
       this( recs == null ? null : recs.toArray(new PwsRecord[recs.size()]) );
	}

	@Override
	protected boolean duplicateInsertion(PwsRecord rec)
			throws DuplicateEntryException {
		return false;
	}

	@Override
	public void addRecordValid(PwsRecord rec) {
		try {
			super.addRecordValid(rec);
		} catch (DuplicateEntryException e) {
		}
	}

	@Override
	public void addRecord(PwsRecord rec) {
		try {
			super.addRecord(rec);
		} catch (DuplicateEntryException e) {
		}
	}

	@Override
	protected PwsRecord addRecordIntern(PwsRecord rec, String report) {
		try {
			return super.addRecordIntern(rec, report);
		} catch (DuplicateEntryException e) {
			return null;
		}
	}

	@Override
	public PwsRecordList addRecordList(PwsRecordList list) {
		try {
			super.addRecordList(list);
		} catch (DuplicateEntryException e) {
		}
		return this;
	}

	@Override
	public PwsRecordList addCollection(Collection<PwsRecord> coll) {
		try {
			super.addCollection(coll);
		} catch (DuplicateEntryException e) {
		}
		return this;
	}

	@Override
	public void replaceContent(PwsRecord[] recs) {
		try {
			super.replaceContent(recs);
		} catch (DuplicateEntryException e) {
		}
	}
	
}
