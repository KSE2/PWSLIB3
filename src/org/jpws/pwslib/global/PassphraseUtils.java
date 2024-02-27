/*
 *  File: PassphraseUtils.java
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

package org.jpws.pwslib.global;

import org.jpws.pwslib.data.PwsPassphrasePolicy;
import org.jpws.pwslib.exception.InvalidPassphrasePolicy;



/**
 * Static utility class to generate random password values complying to a 
 * given <code>PwsPassphrasePolicy</code>.
 * <p>See also {@link org.jpws.pwslib.data.PwsPassphrasePolicy}
 *  
 * @author Kevin Preece
 * @author Wolfgang Keller (slightly modified)
 * @since 0-3-0
 */
public class PassphraseUtils
{
	/**
	 * Standard lowercase characters.
	 */
	public static final char []	LOWERCASE_CHARS			= "abcdefghijklmnopqrstuvwxyz".toCharArray();

	/**
	 * Standard uppercase characters.
	 */
	public static final char []	UPPERCASE_CHARS			= "ABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();

	/**
	 * Standard digit characters.
	 */
	public static final char []	DIGIT_CHARS				= "1234567890".toCharArray();

	/**
	 * Standard symbol characters.
	 */
	public static final char [] SYMBOL_CHARS       =  "!#$%&()+,-./:;<=>?@[\\]^_{|}~".toCharArray();
    /**
     * Standard hexadecimal characters with uppercase alpha.
     */
    public static final char [] HEXADECIMAL_HIGH_CHARS            = "0123456789ABCDEF".toCharArray();

    /**
     * Standard hexadecimal characters with lowercase alpha.
     */
    public static final char [] HEXADECIMAL_LOW_CHARS            = "0123456789abcdef".toCharArray();

	/**
	 * Lowercase characters with confusable characters removed.
	 */
	public static final char []	EASYVISION_LC_CHARS		= "abcdefghijkmnopqrstuvwxyz".toCharArray();

	/**
	 * Uppercase characters with confusable characters removed.
	 */
	public static final char []	EASYVISION_UC_CHARS		= "ABCDEFGHJKLMNPQRTUVWXY".toCharArray();

	/**
	 * Digit characters with confusable characters removed.
	 */
	public static final char []	EASYVISION_DIGIT_CHARS	= "346789".toCharArray();

	/**
	 * Symbol characters with confusable characters removed.
	 */
    public static final char [] EASYVISION_SYMBOL_CHARS = "#$%&+-/<=>?@\\^_~".toCharArray();

    /**
     * Symbol characters which may not occur in a password.
     */
    public static final char [] FORBIDDEN_CHARS = " `´\r\n".toCharArray();

	/**
	 * The minimum length that a password must be to be not weak.
	 */
	public static final int		MIN_PASSWORD_LEN		= 4;

	/**
	 * Private for singleton pattern
	 */
	private PassphraseUtils()
	{
	}

	/**
	 * Generates a new random password according to the policy supplied.
	 * 
	 * @param policy the {@link PwsPassphrasePolicy} policy
	 * 
	 * @return A new random password.
	 * 
	 * @throws InvalidPassphrasePolicy
	 */
	public static char[] makePassword( PwsPassphrasePolicy policy )
	throws InvalidPassphrasePolicy
	{
		char		   allChars [][];
        char[]         result, symbols;
		boolean[]   	typesSeen, typesSeenEx;
		StringBuffer	password;
		int				typeCount, ii;

		if ( !policy.isValid() )
		{
			throw new InvalidPassphrasePolicy();
		}

		password	= new StringBuffer( policy.length );
		typeCount	= 0;

		if ( policy.digitChars )	++typeCount;
		if ( policy.lowercaseChars)	++typeCount;
		if ( policy.uppercaseChars)	++typeCount;
		if ( policy.symbolChars)	++typeCount;
	    if ( policy.hexadecimalChars)  typeCount = 1;

		allChars	= new char[ typeCount ][];
		typesSeen	= new boolean[ 4 ];

		for ( ii = 0; ii < typeCount; ++ii )
		{
			typesSeen[ ii ] = true;
		}

        ii  = 0;
        if ( policy.hexadecimalChars )
        {
           if ( policy.uppercaseChars & !policy.lowercaseChars )
              allChars[ 0 ] = HEXADECIMAL_HIGH_CHARS;
           else
              allChars[ 0 ] = HEXADECIMAL_LOW_CHARS;
        }
        else if ( policy.easyview )
		{
			if ( policy.digitChars )	allChars[ ii++ ] = EASYVISION_DIGIT_CHARS;
			if ( policy.lowercaseChars)	allChars[ ii++ ] = EASYVISION_LC_CHARS;
			if ( policy.uppercaseChars)	allChars[ ii++ ] = EASYVISION_UC_CHARS;
			if ( policy.symbolChars)	allChars[ ii++ ] = 
			    policy.hasOwnSymbols() ? policy.getOwnSymbols() : EASYVISION_SYMBOL_CHARS;
		}
		else
		{
			if ( policy.digitChars )	allChars[ ii++ ] = DIGIT_CHARS;
			if ( policy.lowercaseChars)	allChars[ ii++ ] = LOWERCASE_CHARS;
			if ( policy.uppercaseChars)	allChars[ ii++ ] = UPPERCASE_CHARS;
			if ( policy.symbolChars)	allChars[ ii++ ] = 
			     policy.hasOwnSymbols() ? policy.getOwnSymbols() :  SYMBOL_CHARS;
		}

      do
		{
			password.delete( 0, password.length() );
            typesSeenEx = (boolean[]) typesSeen.clone();

			for ( ii = 0; ii < policy.length; ++ii )
			{
				int	type;
				char[] typeSet;
	
				type = Util2.getCryptoRand().nextInt( typeCount );
				typesSeenEx[ type ]	= false;
				typeSet = allChars[type];
	
				password.append( typeSet[ Util2.getCryptoRand().nextInt( typeSet.length ) ] );
			}
		}
		while ( typesSeenEx[0] || typesSeenEx[1] || typesSeenEx[2] || typesSeenEx[3] );

		// extract resulting char array
      result = new char[ password.length() ];
      password.getChars( 0, password.length(), result, 0 );

      // destroy StringBuffer
      for ( int i = 0; i < password.length(); i++ )
         password.setCharAt( i, '\u0000' );
         
	  return result;
	}

	/**
	 * Checks the password against a set of rules to determine whether it is
	 * considered weak.  The rules are:
	 * </p><p>
	 * <ul>
	 *   <li>It is at least <code>MIN_PASSWORD_LEN</code> characters long.
	 *   <li>At least one lowercase character.
	 *   <li>At least one uppercase character.
	 *   <li>At least one digit or symbol character.
	 * </ul>
	 * 
	 * @param password the password to check.
	 * 
	 * @return <code>true</code> if the password is considered to be weak,
	 *         <code>false</code> otherwise.
	 */
	public static boolean isWeakPassword( char[] password )
	{
		boolean	hasUC		= false;
		boolean	hasLC		= false;
		boolean	hasDigit	= false;
		boolean	hasSymbol	= false;

		if ( password.length < MIN_PASSWORD_LEN )
		{
			return true;
		}

		for ( int ii = 0; ii < password.length; ++ii )
		{
			char	c;

			c = password[ ii ];

			if ( Character.isDigit(c) )				hasDigit	= true;
			else if ( Character.isUpperCase(c) )	hasUC		= true;
			else if ( Character.isLowerCase(c) )	hasLC		= true;
			else 									hasSymbol	= true;
		}

		if ( hasUC && hasLC && (hasDigit || hasSymbol) )
		{
			return false;
		}
		return true;
	}
}
