/*
 *  File: Collatable.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 28.08.2005
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

import java.text.CollationKey;

/**
 *  Defining a class which bears a <code>CollationKey</code>. 
 */
public interface Collatable
{

   CollationKey getCollationKey();
   
}
