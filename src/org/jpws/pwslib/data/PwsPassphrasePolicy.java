/*
 *  File: PwsPassphrasePolicy.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 07.08.2005
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

import org.jpws.pwslib.global.Log;
import org.jpws.pwslib.global.PassphraseUtils;
import org.jpws.pwslib.global.Util;

/**
 * This class defines a policy that is used to generate a random password.
 * The policy defines how long the generated password should be and which
 * character classes it should contain. The maximum password length is 256.
 * The possible character classes are:
 * <p>
 * <sl>
 *   <li>Upper case letters,
 *   <li>Lowercase letters,
 *   <li>Digits
 *   <li>certain symbol characters.
 * </sl>
 * </p>
 * <p>In addition it also specifies whether certain mistakable characters should
 * be removed from the password. These are e.g. characters such as '1' and 'I'.
 */
public class PwsPassphrasePolicy implements Cloneable
{
   /** The maximum password length this policy can set up. Value is 256. */
   public static final int MAXKEYLENGTH = 256;
   
   /** The default password length for this policy (8 characters). */
   public static final int DEFAULT_KEYLENGTH = 8;
   
	/**
	 * <code>true</code> if generated password should contain lowercase characters.
	 * The default is <code>true</code>.
	 */
	public boolean	lowercaseChars;

	/**
	 * <code>true</code> if generated password should contain uppercase characters.
	 * The default is <code>true</code>.
	 */
	public boolean	uppercaseChars;

	/**
	 * <code>true</code> if generated password should contain digit characters.
	 * The default is <code>true</code>.
	 */
	public boolean	digitChars;

	/**
	 * <code>true</code> if the generated password should contain symbol characters.
	 * The default is <code>true</code>.
	 */
	public boolean	symbolChars;

    /**
     * <code>true</code> if the generated password should contain ONLY hexadecimal
     *  characters. If this value is true, only <tt>uppercaseChars</tt> and 
     *  <tt>lowercaseChars</tt> are of possible additional interest for password creation.  
     *  The default is <code>false</code>.
     */
    public boolean  hexadecimalChars;

	/**
	 * <code>true</code> if the generated password should not contain confusable characters.
	 * The default is <code>false</code>.
	 */
	public boolean	easyview;

    /**
     * <code>true</code> if the generated password should be pronounceable.
     * Whatever that is, this certainly is no good random password any more!
     * This setting isn't used by JPWS and appears for compatibility with
     * PWS format 3.6 only.
     * The default is <code>false</code>.
     */
    private boolean  pronounceable;

    /** Set of personal symbols defined for password
     * generation. This feature is independent of whether use
     * of symbols is activated. <b>null</b> deactivates.
     */
    private char[] ownSymbols;

	/**
	 * The length of the generated password.  The default is 8.
	 */
	public int		length;

	private int     minimumLowercase = 1;
    private int     minimumUppercase = 1;
    private int     minimumDigits = 1;
    private int     minimumSymbols = 1;
	
	/**
	 * Creates a password policy with fairly strong defaults.  If unaltered
	 * this policy will cause a password to be generated that is 8 characters
	 * long with at least one of each character class, i.e. at least one
	 * uppercase, lowercase, digit, and symbol characters.
	 */
	public PwsPassphrasePolicy()
	{
	   defaults();
	}

   /**
    * Creates a password policy with initial settings drawn from the parameter
    * integer representation. There is no check for validity of this policy
    * in this constructor!
    * 
    * @param value an integer representation of a passphrase poliy as obtainable
    *        through the <code>getIntForm()</code> method of this class;
    *        if 0 this constructor is equal to the empty constructor
    */
   public PwsPassphrasePolicy( int value )
   {
      if ( value > 0 ) {
         setFromInt( value );
      } else {
         defaults();
      }
   }

   /** 
    * Creates a password policy from a "modern" or "internal" serialisation string.
    * 
    * @param value String modern or internal serialised form
    */
	public PwsPassphrasePolicy ( String value )
   {
	   if ( value != null ) {
	      if ( value.length() > 19 ) {
	         setFromInternal( value );
	      } else {
	         setFromModern( value );
	      }
	   } else {
	      defaults();
	   }
   }

   private void defaults ()
   {
      length = DEFAULT_KEYLENGTH;
      lowercaseChars = true;
      uppercaseChars = true;
      digitChars = true;
      symbolChars = false;
      easyview = false;
      hexadecimalChars = false;
      pronounceable = false;
   }
	
   /**
	 * Checks that it is possible to generate a password using this policy.  Returns
	 * <code>true</code> if at least one character category is selected and the password
	 * length is equal to or greater than the number of classes selected.
	 */
	public boolean isValid()
	{
		int		count	= 0;
		if ( lowercaseChars )	++count;
		if ( uppercaseChars )	++count;
		if ( digitChars )		++count;
		if ( symbolChars )		++count;

        return (hexadecimalChars ? length > 0 : count > 0 & length >= count)
               & length <= MAXKEYLENGTH;
	}
   
	/** Whether this policy bears the generator feature to
	 * create EASYVIEW characters only.
	 * 
	 * @return boolean <b>true</b> == EASYVIEW
	 */
	public boolean isEasyView ()
	{
	   return easyview;
	}
	
	public boolean hasOwnSymbols ()
	{
	   return ownSymbols != null;
	}
	
   /** Completely sets up this policy from an integer representation. */ 
   public void setFromInt ( int v )
   {
      length = v & 0xffff;
      
      int h = ( v >>> 16 ) & 0xffff;
      lowercaseChars = ( h & 1 ) == 1;
      uppercaseChars = ( h & 2 ) == 2;
      digitChars = ( h & 4 ) == 4;
      symbolChars = ( h & 8 ) == 8;
      easyview = ( h & 16 ) == 16;
      hexadecimalChars = ( h & 32 ) == 32;
   }
	   
	/** Returns an integer representation of this policy. */
   public int getIntForm ()
   {
      int v = length;
      
      int h = 0;
      if ( lowercaseChars )
         h |= 1; 
      if ( uppercaseChars )
         h |= 2; 
      if ( digitChars )
         h |= 4; 
      if ( symbolChars )
         h |= 8; 
      if ( easyview )
         h |= 16; 
      if ( hexadecimalChars )
         h |= 32; 
      
      v |= h << 16; 
      return v;
   }
   
   /** Returns the latest "modern" representation of this policy. 
    * (This is used in PWS Format 3.6 and does NOT include the "own symbols" 
    * content)
    * 
    * @return String of length 19
    */
   public String getModernForm ()
   {
// previous code (correct definition version)
//      // logic code
//      int h = 0;
//      if ( hexadecimalChars ) {
//         h = 0x0800;
//      } else {
//         if ( lowercaseChars )
//            h = 0x8000; 
//         if ( uppercaseChars )
//            h |= 0x4000; 
//         if ( digitChars )
//            h |= 0x2000; 
//         if ( symbolChars )
//            h |= 0x1000; 
//         if ( easyview )
//            h |= 0x0400;
//         if ( pronounceable & !easyview )
//            h |= 0x0200;
//      }

      // correction of unambiguous case setting in HEXADECIMAL priority mode
      if ( hexadecimalChars & (lowercaseChars == uppercaseChars) ) {
         lowercaseChars = true;
         uppercaseChars = false;
      }

      // logic code
      int h = 0;
      if ( hexadecimalChars )
         h = 0x0800;
      if ( lowercaseChars )
         h |= 0x8000; 
      if ( uppercaseChars )
         h |= 0x4000; 
      if ( digitChars )
         h |= 0x2000; 
      if ( symbolChars )
         h |= 0x1000; 
      if ( easyview )
         h |= 0x0400;
      if ( pronounceable & !easyview )
         h |= 0x0200;
      String v = Util.intToHex( h ).substring(4);
      
      // value length code (3 unsigned hex digits)
      String hstr = Util.intToHex( length ).substring(5);
      v += hstr;
      
      // minimum occurrences values 
      // (JPWS does not use them, this is for compatibility with other apps)
      v += lowercaseChars ? Util.intToHex( minimumLowercase ).substring(5) : "000";
      v += uppercaseChars ? Util.intToHex( minimumUppercase ).substring(5) : "000";
      v += digitChars ? Util.intToHex( minimumDigits ).substring(5) : "000";
      v += symbolChars ? Util.intToHex( minimumSymbols ).substring(5) : "000";
      return v;
   }
   
   /** Returns an "internal" serialised format of this policy
    * usable in programmatic context (not a canonical format!).
    * 
    * @return String internal text representation of pw-policy
    */
   public String getInternalForm ()
   {
      // leading canonical format (without own symbols)
      String lead = getModernForm();
      
      // add "own symbols"
      if ( hasOwnSymbols() ) {
         lead += Util.shortToHex( ownSymbols.length ) + new String(ownSymbols);  
      } else {
         lead += "0000";
      }
      return lead;
   }
   
   /** Completely sets up this policy from a "modern" representation 
    * (as used in PWS format 3.6). If the value is corrupted, the class'es
    * default values are set. Reads the first 19 bytes of the input.
    * 
    *  @param v String modern string representation of policy
    */ 
   public void setFromModern ( String v )
   {
      if ( v == null )
         throw new NullPointerException();
      
      try {
         // read the definiens values
         int h = Integer.parseInt( v.substring( 0, 4 ), 16 );
         length = Integer.parseInt( v.substring( 4, 7 ), 16 );
         minimumLowercase = Integer.parseInt( v.substring( 7, 10 ), 16 );
         minimumUppercase = Integer.parseInt( v.substring( 10, 13 ), 16 );
         minimumDigits = Integer.parseInt( v.substring( 13, 16 ), 16 );
         minimumSymbols = Integer.parseInt( v.substring( 16, 19 ), 16 );
         
         // analyse
         hexadecimalChars = ( h & 0x0800 ) == 0x0800;
         lowercaseChars = ( h & 0x8000 ) == 0x8000;
         uppercaseChars = ( h & 0x4000 ) == 0x4000;
         digitChars = ( h & 0x2000 ) == 0x2000;
         symbolChars = ( h & 0x1000 ) == 0x1000;
         easyview = ( h & 0x0400 ) == 0x0400;
         pronounceable = ( h & 0x0200 ) == 0x0200;

         if ( hexadecimalChars & (lowercaseChars == uppercaseChars) ) {
            lowercaseChars = true;
            uppercaseChars = false;
         }
// previous method (correct to definition)         
//         // analyse
//         hexadecimalChars = ( h & 0x0800 ) == 0x0800;
//         if ( !hexadecimalChars )
//         {
//            lowercaseChars = ( h & 0x8000 ) == 0x8000;
//            uppercaseChars = ( h & 0x4000 ) == 0x4000;
//            digitChars = ( h & 0x2000 ) == 0x2000;
//            symbolChars = ( h & 0x1000 ) == 0x1000;
//            easyview = ( h & 0x0400 ) == 0x0400;
//            pronounceable = ( h & 0x0200 ) == 0x0200;
//         }
         
      } catch ( Exception e ) { 
    	  defaults(); 
      }
   }
   
   /** Completely defines this policy by reading from the
    * "internal" serialised format (non-canonical).
    * 
    * @param v String internal format serialisation of policy 
    */
   public void setFromInternal ( String v )
   {
      // use the leading "modern" form
      setFromModern( v );
      
      // read own symbols set
      try {
         // read length info
         int len = Integer.parseInt( v.substring( 19, 23 ), 16 );
         String hstr = v.substring( 23, 23+len );
         ownSymbols = len == 0 ? null : hstr.toCharArray();
         
      } catch ( Exception e ) { 
    	  e.printStackTrace(); 
      }
   }
   
   /** Returns the set of personal symbols for this passphrase policy.
    * 
    * @return char[] with symbols or <b>null</b> if unavailable
    */
   public char[] getOwnSymbols ()
   {
      return ownSymbols;
   }
   
   /** Returns the set of symbols which are currently relevant
    * for this passphrase policy. ("Active" here does not imply that
    * symbols are selected for password generation!) 
    * 
    * @return char[] with symbols or <b>null</b> if feature is void 
    */
   public char[] getActiveSymbols ()
   {
      return hasOwnSymbols() ? ownSymbols : 
             easyview ? PassphraseUtils.EASYVISION_SYMBOL_CHARS : 
             PassphraseUtils.SYMBOL_CHARS;
   }
   
   /** Sets or removes personal symbols for this passphrase policy.
    *  
    * @param symbols char[] set of symbols or <b>null</b> for remove
    */
   public void setOwnSymbols ( char[] symbols )
   {
      ownSymbols = symbols == null ? null : (char[])symbols.clone();
      ownSymbols = Util.clearedSymbolSet( ownSymbols ); 
      if ( Util.equalArrays( ownSymbols, PassphraseUtils.SYMBOL_CHARS ) & !easyview ||
           Util.equalArrays( ownSymbols, PassphraseUtils.EASYVISION_SYMBOL_CHARS ) & easyview )
         ownSymbols = null;
      ownSymbols = Util.excludeCharset( ownSymbols, PassphraseUtils.DIGIT_CHARS );
      ownSymbols = Util.excludeCharset( ownSymbols, PassphraseUtils.UPPERCASE_CHARS );
      ownSymbols = Util.excludeCharset( ownSymbols, PassphraseUtils.LOWERCASE_CHARS );
      ownSymbols = Util.excludeCharset( ownSymbols, PassphraseUtils.FORBIDDEN_CHARS );
      
      Log.debug( 10, "(PwsPassphrasePolicy.setOwnSymbols) setting own symbols == [" + 
            (ownSymbols == null ? null : new String(ownSymbols)) + "]"); 
   }
   
   public Object clone ()
   {
      try { 
    	  return super.clone(); 
      } catch ( CloneNotSupportedException e ) { 
    	  return null; 
      }
   }
   
	/**
	 * Returns a <code>String</code> representation of the object, which is 
	 * meant to be human readable.
	 * 
	 * @return <code>String</code> representation of the object.
	 */
	public String toString()
	{
		StringBuffer sb = new StringBuffer();

		sb.append( "PwsPassphrasePolicy{ Length=" );
		sb.append( length );
		sb.append( ", Uppercase=" );
		sb.append( uppercaseChars );
		sb.append( ", Lowercase=" );
		sb.append( lowercaseChars );
		sb.append( ", Digits=" );
		sb.append( digitChars );
		sb.append( ", Symbols=" );
		sb.append( symbolChars );
        sb.append( ", Hexadecimal=" );
        sb.append( hexadecimalChars );
		sb.append( ", Easyview=" );
		sb.append( easyview );
		if ( hasOwnSymbols() ) {
		   sb.append( ", Own Symbols=" );
		   sb.append( new String( ownSymbols ) );
		}
		sb.append( " }" );

		return sb.toString();
	}
   
   /** Whether this policy equals in value another policy. Two policies are equal
    *  if and only if their integer representations are equal.
    * 
    *  @param obj <code>Object</code>, may be null 
    */
   public boolean equals ( Object obj )
   {
      if ( obj != null && obj instanceof PwsPassphrasePolicy ) {
         PwsPassphrasePolicy pol = (PwsPassphrasePolicy)obj;
         String symbols = new String ( pol.getActiveSymbols() );
         return pol.getIntForm() == getIntForm() && 
                symbols.equals( new String( getActiveSymbols() ));
      }
      return false; 
   }
   
   /** <code>equals()</code> compatible hashcode function. 
    */
   public int hashCode ()
   {
      return getIntForm();
   }
}
