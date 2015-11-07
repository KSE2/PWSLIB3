/*
 *  File: DefaultUrlAdapter.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 06.08.2004
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

package org.jpws.pwslib.persist;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;

/**
 * Implements a straight forward <code>ApplicationAdapter</code> for addressing
 * URL protocol files, based on the java.net package.
 *  
 */
public class DefaultUrlAdapter implements ApplicationAdapter
{
   protected static int classID = 22; 
   protected static DefaultUrlAdapter instance = new DefaultUrlAdapter();

/**
 * Constructs an instance.
 */
private DefaultUrlAdapter ()
{
}

/** Returns the singleton instance of this class. */ 
public static DefaultUrlAdapter get ()
{
   return instance;
}

@Override
public InputStream getInputStream ( String path ) throws IOException
{
   URL url = new URL( path );
   URLConnection urlCon = url.openConnection();
   urlCon.setAllowUserInteraction( true );
   //urlCon.connect();

   return urlCon.getInputStream();
}

@Override
public OutputStream getOutputStream ( String path ) throws IOException
{
   URL url = new URL( path );
   URLConnection urlCon = url.openConnection();
   urlCon.setAllowUserInteraction( true );
   urlCon.setDoOutput( true );
   //urlCon.connect();

   return urlCon.getOutputStream();
}

@Override
public String getName ()
{
   return "URL File Locations";
}

@Override
public int getType ()
{
   return INTERNET;
}

@Override
public boolean deleteFile ( String path ) throws IOException
{
   return false;
}

@Override
public boolean existsFile ( String path ) throws IOException
{
   try {
      URL url = new URL( path );
      URLConnection urlCon = url.openConnection();
      urlCon.connect();
      return urlCon.getLastModified() > 0;

   } catch ( FileNotFoundException e ) {
      return false;
   }
}

@Override
public boolean renameFile ( String path, String newPath ) throws IOException
{
   return false;
}

@Override
public void lockFileAccess ( String path ) throws IOException
{
   // no-op
}

@Override
public void unlockFileAccess ( String path ) throws IOException
{
   // no-op
}

@Override
public boolean canWrite ( String path )
{
   return false;
}

@Override
public boolean canRead ( String path ) throws IOException
{
   return existsFile( path );
}

@Override
public boolean canDelete ( String path )
{
   return false;
}

@Override
public long getFileLength ( String path ) throws IOException
{
   URL url = new URL( path );
   URLConnection urlCon = url.openConnection();
   urlCon.connect();
   return urlCon.getContentLength();
}

@Override
public long getModifiedTime ( String path ) throws IOException
{
   URL url = new URL( path );
   URLConnection urlCon = url.openConnection();
   urlCon.connect();
   return urlCon.getLastModified();
}

/** An object equals this adapter if it is an instance of 
 * <code>DefaultUrlAdapter</code>.
 */
@Override
public boolean equals ( Object obj )
{
   return obj != null && obj instanceof DefaultUrlAdapter;
}

@Override
public int hashCode ()
{
   return classID;
}

@Override
public String[] list ( String trunk, String trail, boolean recurse ) 
			throws IOException
{
   return null;
}

@Override
public String separator ()
{
   return "/";
}

@Override
public URL getUrl ( String filepath ) throws IOException
{
   URL url = new URL( filepath );
   return url;
}

@Override
public boolean setModifiedTime ( String path, long time ) throws IOException
{
   return false;
}
}
