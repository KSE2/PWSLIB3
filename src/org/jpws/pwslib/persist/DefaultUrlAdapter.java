/*
 *  DefaultFilesystemAdapter in org.jpws.pwslib.persist
 *  file: DefaultFilesystemAdapter.java
 * 
 *  Project JPasswords
 *  @author Wolfgang Keller
 *  Created 06.08.2004
 *  Version 
 * 
 *  Copyright (c) 2005 by Wolfgang Keller, Munich, Germany
 * 
 This program is not freeware software but copyright protected to the author(s)
 stated above. However, you can use, redistribute and/or modify it under the terms 
 of the GNU General Public License as published by the Free Software Foundation, 
 version 2 of the License.

 This program is distributed in the hope that it will be useful, but WITHOUT
 ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

 You should have received a copy of the GNU General Public License along with
 this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 Place - Suite 330, Boston, MA 02111-1307, USA, or go to
 http://www.gnu.org/copyleft/gpl.html.
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
 *  @since 0-3-0
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

/* (non-Javadoc)
 * @see org.jpws.pwslib.global.ApplicationAdapter#getInputStream(java.lang.String)
 */
public InputStream getInputStream ( String path ) throws IOException
{
   URLConnection urlCon;
   URL url;

   url = new URL( path );
   urlCon = url.openConnection();
   urlCon.setAllowUserInteraction( true );
   //urlCon.connect();

   return urlCon.getInputStream();
}

/* (non-Javadoc)
 * @see org.jpws.pwslib.global.ApplicationAdapter#getOutputStream(java.lang.String)
 */
public OutputStream getOutputStream ( String path ) throws IOException
{
   URLConnection urlCon;
   URL url;

   url = new URL( path );
   urlCon = url.openConnection();
   urlCon.setAllowUserInteraction( true );
   urlCon.setDoOutput( true );
   //urlCon.connect();

   return urlCon.getOutputStream();
}

/* (non-Javadoc)
 * @see org.jpws.pwslib.global.ApplicationAdapter#getName()
 */
public String getName ()
{
   return "URL File Locations";
}

/* (non-Javadoc)
 * @see org.jpws.pwslib.global.ApplicationAdapter#getType()
 */
public int getType ()
{
   return INTERNET;
}

/* (non-Javadoc)
 * @see org.jpws.pwslib.global.ApplicationAdapter#deleteFile(java.lang.String)
 */
public boolean deleteFile ( String path ) throws IOException
{
   return false;
}

/* (non-Javadoc)
 * @see org.jpws.pwslib.global.ApplicationAdapter#existsFile(java.lang.String)
 */
public boolean existsFile ( String path ) throws IOException
{
   URLConnection urlCon;
   URL url;

   try {
      url = new URL( path );
      urlCon = url.openConnection();
      urlCon.connect();
      return urlCon.getContentLength() > -1;
   }
   catch ( FileNotFoundException e )
   {
      return false;
   }
}

/* (non-Javadoc)
 * @see org.jpws.pwslib.global.ApplicationAdapter#renameFile(java.lang.String,java.lang.String)
 */
public boolean renameFile ( String path, String newPath ) throws IOException
{
   return false;
}

public void lockFileAccess ( String path ) throws IOException
{
   // no-op
}

public void unlockFileAccess ( String path ) throws IOException
{
   // no-op
}

/* (non-Javadoc)
 * @see org.jpws.pwslib.global.ApplicationAdapter#canWrite()
 */
public boolean canWrite ( String path )
{
   return false;
}

/* (non-Javadoc)
 * @see org.jpws.pwslib.global.ApplicationAdapter#canRead()
 */
public boolean canRead ( String path ) throws IOException
{
   return existsFile( path );
}

/* (non-Javadoc)
 * @see org.jpws.pwslib.global.ApplicationAdapter#canWrite()
 */
public boolean canDelete ( String path )
{
   return false;
}

public long getFileLength ( String path ) throws IOException
{
   URLConnection urlCon;
   URL url;

   url = new URL( path );
   urlCon = url.openConnection();
   urlCon.connect();
   return urlCon.getContentLength();
}

public long getModifiedTime ( String path ) throws IOException
{
   URLConnection urlCon;
   URL url;

   url = new URL( path );
   urlCon = url.openConnection();
   urlCon.connect();
   return urlCon.getLastModified();
}

/** An object equals this adapter if it is an instance of <code>DefaultUrlAdapter
 *  </code>.
 */
public boolean equals ( Object obj )
{
   return obj != null && obj instanceof DefaultUrlAdapter;
}

public int hashCode ()
{
   return classID;
}

public String[] list ( String trunk, String trail, boolean recurse ) throws IOException
{
   return null;
}

public String separator ()
{
   return "/";
}

public URL getUrl ( String filepath ) throws IOException
{
   URL url;
   
   url = new URL( filepath );
   return url;
}

public boolean setModifiedTime ( String path, long time ) throws IOException
{
   return false;
}



}
