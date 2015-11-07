/*
 *  File: TestC_RawFields.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 07.02.2007
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

import junit.framework.TestCase;

public class TestC_RawFields extends TestCase
{

public TestC_RawFields ()
{
   super();
}

public TestC_RawFields ( String name )
{
   super( name );
}

public void test_RawField ()
{
   PwsRawField f1, f2;
   int type;
   byte[] d1, d2;
   String tstr1;
   
   // test constructors
   // 0 - null
   f1 = new PwsRawField( 0, null );
   assertTrue( "Con-1 type integrity", f1.getType() == 0 );
   assertTrue( "Con-1 data integrity 1", f1.getData() != null );
   assertTrue( "Con-1 data integrity 2", f1.getData().length == 0 );
   assertTrue( "Con-1 block amount integrity V1", f1.getBlockCount(1) == 2 );
   assertTrue( "Con-1 block amount integrity V2", f1.getBlockCount(2) == 2 );
   assertTrue( "Con-1 block amount integrity V3", f1.getBlockCount(3) == 1 );
   assertTrue( "Con-1 blocked size integrity V1", f1.getBlockedSize(1) == 16 );
   assertTrue( "Con-1 blocked size integrity V2", f1.getBlockedSize(2) == 16 );
   assertTrue( "Con-1 blocked size integrity V3", f1.getBlockedSize(3) == 16 );
   assertTrue( "Con-1 get String integrity", f1.getString(null).length() == 0 );
   assertTrue( "Con-1 get Passphrase integrity", f1.getPassphrase(null).getLength() == 0 );
   f2 = new PwsRawField( 0, null );
   assertTrue( "Con-1 \"equals\" integrity", f1.equals( f2 ) );
   assertTrue( "Con-1 \"hashcode\" integrity", f1.hashCode() == f2.hashCode() );
   System.out.println( "PwsRawField hashcode == " + f1.hashCode() );
   
   // 0 - empty array
   f1 = new PwsRawField( 0, new byte[0] );
   assertTrue( "Con-2 type integrity", f1.getType() == 0 );
   assertTrue( "Con-2 data integrity 1", f1.getData() != null );
   assertTrue( "Con-2 data integrity 2", f1.getData().length == 0 );
   assertTrue( "Con-2 block amount integrity V1", f1.getBlockCount(1) == 2 );
   assertTrue( "Con-2 block amount integrity V2", f1.getBlockCount(2) == 2 );
   assertTrue( "Con-2 block amount integrity V3", f1.getBlockCount(3) == 1 );
   assertTrue( "Con-2 blocked size integrity V1", f1.getBlockedSize(1) == 16 );
   assertTrue( "Con-2 blocked size integrity V2", f1.getBlockedSize(2) == 16 );
   assertTrue( "Con-2 blocked size integrity V3", f1.getBlockedSize(3) == 16 );
   assertTrue( "Con-2 get String integrity", f1.getString(null).length() == 0 );
   assertTrue( "Con-2 get Passphrase integrity", f1.getPassphrase(null).getLength() == 0 );
   f2 = new PwsRawField( 0, new byte[0] );
   assertTrue( "Con-2 \"equals\" integrity", f1.equals( f2 ) );
   assertTrue( "Con-2 \"hashcode\" integrity", f1.hashCode() == f2.hashCode() );
   System.out.println( "PwsRawField hashcode == " + f1.hashCode() );
   
   // 1 - empty array
   f1 = new PwsRawField( 1, new byte[0] );
   assertTrue( "Con-3 type integrity", f1.getType() == 1 );
   assertTrue( "Con-3 data integrity 1", f1.getData() != null );
   assertTrue( "Con-3 data integrity 2", f1.getData().length == 0 );
   assertTrue( "Con-3 block amount integrity V1", f1.getBlockCount(1) == 2 );
   assertTrue( "Con-3 block amount integrity V2", f1.getBlockCount(2) == 2 );
   assertTrue( "Con-3 block amount integrity V3", f1.getBlockCount(3) == 1 );
   assertTrue( "Con-3 blocked size integrity V1", f1.getBlockedSize(1) == 16 );
   assertTrue( "Con-3 blocked size integrity V2", f1.getBlockedSize(2) == 16 );
   assertTrue( "Con-3 blocked size integrity V3", f1.getBlockedSize(3) == 16 );
   assertTrue( "Con-3 get String integrity", f1.getString(null).length() == 0 );
   assertTrue( "Con-3 get Passphrase integrity", f1.getPassphrase(null).getLength() == 0 );
   f2 = new PwsRawField( 1, null );
   assertTrue( "Con-3 \"equals\" integrity", f1.equals( f2 ) );
   assertTrue( "Con-3 \"hashcode\" integrity", f1.hashCode() == f2.hashCode() );
   System.out.println( "PwsRawField hashcode == " + f1.hashCode() );

   // 1 - "ABCDE" - array
   tstr1 = "ABCDE";
   f1 = new PwsRawField( 1,  tstr1.getBytes() );
   assertTrue( "Con-3 type integrity", f1.getType() == 1 );
   assertTrue( "Con-3 data integrity 1", f1.getData() != null );
   assertTrue( "Con-3 data integrity 2", f1.getData().length == 5 );
   assertTrue( "Con-3 block amount integrity V1", f1.getBlockCount(1) == 2 );
   assertTrue( "Con-3 block amount integrity V2", f1.getBlockCount(2) == 2 );
   assertTrue( "Con-3 block amount integrity V3", f1.getBlockCount(3) == 1 );
   assertTrue( "Con-3 blocked size integrity V1", f1.getBlockedSize(1) == 16 );
   assertTrue( "Con-3 blocked size integrity V2", f1.getBlockedSize(2) == 16 );
   assertTrue( "Con-3 blocked size integrity V3", f1.getBlockedSize(3) == 16 );
   assertEquals( "Con-3 get String integrity", f1.getString(null), tstr1 );
   assertEquals( "Con-3 get Passphrase integrity", f1.getPassphrase(null).getString(), tstr1 );
   f2 = new PwsRawField( 1, tstr1.getBytes() );
   assertTrue( "Con-3 \"equals\" integrity", f1.equals( f2 ) );
   assertTrue( "Con-3 \"hashcode\" integrity", f1.hashCode() == f2.hashCode() );
   System.out.println( "PwsRawField hashcode == " + f1.hashCode() );

   // 255 - "ABCDE" - array
   tstr1 = "ABCDEFG_GFEDCBA";
   f1 = new PwsRawField( 255,  tstr1.getBytes() );
   assertTrue( "Con-4 type integrity", f1.getType() == 255 );
   assertTrue( "Con-4 data integrity 1", f1.getData() != null );
   assertTrue( "Con-4 data integrity 2", f1.getData().length == 15 );
   assertTrue( "Con-4 block amount integrity V1", f1.getBlockCount(1) == 3 );
   assertTrue( "Con-4 block amount integrity V2", f1.getBlockCount(2) == 3 );
   assertTrue( "Con-4 block amount integrity V3", f1.getBlockCount(3) == 2 );
   assertTrue( "Con-4 blocked size integrity V1", f1.getBlockedSize(1) == 24 );
   assertTrue( "Con-4 blocked size integrity V2", f1.getBlockedSize(2) == 24 );
   assertTrue( "Con-4 blocked size integrity V3", f1.getBlockedSize(3) == 32 );
   assertEquals( "Con-4 get String integrity", f1.getString(null), tstr1 );
   assertEquals( "Con-4 get Passphrase integrity", f1.getPassphrase(null).getString(), tstr1 );

   assertFalse( "Con-4 \"equals\" integrity A", f1.equals( f2 ) );
   assertFalse( "Con-4 \"hashcode\" integrity", f1.hashCode() == f2.hashCode() );
   f2 = new PwsRawField( 255, tstr1.getBytes() );
   assertTrue( "Con-4 \"equals\" integrity B", f1.equals( f2 ) );
   assertTrue( "Con-4 \"hashcode\" integrity", f1.hashCode() == f2.hashCode() );
   System.out.println( "PwsRawField hashcode == " + f1.hashCode() );

   
   
}

}
