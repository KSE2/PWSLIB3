/*
 *  File: LoginFailureException.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 2006
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

package org.jpws.pwslib.exception;

import java.io.IOException;

/** Thrown to indicate that an attempt to login into some device
 * or network repository has failed.
 *  
 * @author wolfgang keller
 *
 */
public class LoginFailureException extends IOException {

    public LoginFailureException() {
    }

    public LoginFailureException(String message) {
        super(message);
    }


    
}
