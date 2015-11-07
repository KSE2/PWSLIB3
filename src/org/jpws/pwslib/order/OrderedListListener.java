/*
 *  File: OrderedListListener.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 28.09.2004
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

package org.jpws.pwslib.order;

/**
 *  Interface for a listener to an ordered record list as represented  by the
 *  class <code>OrderedRecordList</code>.
 *  <p>See also {@link OrderedListEvent}, {@link OrderedRecordList}

 */
public interface OrderedListListener
{

public void orderedListPerformed ( OrderedListEvent evt );
   
}
