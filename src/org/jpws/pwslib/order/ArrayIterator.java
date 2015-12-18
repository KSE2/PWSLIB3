package org.jpws.pwslib.order;

import java.util.Iterator;
import java.util.NoSuchElementException;

public class ArrayIterator<T> implements Iterator<T> {

	private T[] arr;
	private int p;
	
	public ArrayIterator (T[] array) {
		if (array == null)
			throw new NullPointerException();
		
		arr = array;
	}

	@Override
	public boolean hasNext() {
		return p < arr.length;
	}

	@Override
	public T next() {
		if ( !hasNext() ) 
			throw new NoSuchElementException();
		
		T obj = arr[p++];
		return obj;
	}
}
