/*
 *  File: PwsFileListener.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 27.09.2004
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

/**
 *  Interface defines a state change notification method for listeners for
 *  PWS record lists and their modifications. The type of events that may be 
 *  issued are defined by the <code>PwsFileEvent</code> class. 
 *  
 *  @see org.jpws.pwslib.data.PwsRecordList
 */
public interface PwsFileListener
{
   public void fileStateChanged ( PwsFileEvent evt );
}
