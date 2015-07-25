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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import org.jpws.pwslib.global.Log;
import org.jpws.pwslib.global.Util;

/**
 * Implements a straight forward <code>ApplicationAdapter</code> for the
 * local file system, based on the java.io package. This is the default 
 * standard application installed by the <code>Global.init</code> function.
 */

public class DefaultFilesystemAdapter implements ApplicationAdapter
{
   protected static int classID = 11;
   protected static DefaultFilesystemAdapter instance = new DefaultFilesystemAdapter();

   private HashMap filesMap = new HashMap(); 
   
/**
 * Constructs an instance.
 */
private DefaultFilesystemAdapter ()
{
}

/** Returns the singleton instance of this class. */ 
public static DefaultFilesystemAdapter get ()
{
   return instance;
}

/* (non-Javadoc)
 * @see org.jpws.pwslib.global.ApplicationAdapter#getInputStream(java.lang.String)
 */
public InputStream getInputStream ( String path ) throws IOException
{
   return new FileInputStream( path );
}

/* (non-Javadoc)
 * @see org.jpws.pwslib.global.ApplicationAdapter#getOutputStream(java.lang.String)
 */
public OutputStream getOutputStream ( String path ) throws IOException
{
   return new OurOutputStream( path, isLockedFile( path ) );
}

/* (non-Javadoc)
 * @see org.jpws.pwslib.global.ApplicationAdapter#getName()
 */
public String getName ()
{
   return "Local Files";
}

/* (non-Javadoc)
 * @see org.jpws.pwslib.global.ApplicationAdapter#getType()
 */
public int getType ()
{
   return FILESYSTEM;
}

/* (non-Javadoc)
 * @see org.jpws.pwslib.global.ApplicationAdapter#deleteFile(java.lang.String)
 */
public boolean deleteFile ( String path ) throws IOException
{
   return new File( path ).delete();
}

/* (non-Javadoc)
 * @see org.jpws.pwslib.global.ApplicationAdapter#existsFile(java.lang.String)
 */
public boolean existsFile ( String path ) throws IOException
{
   return new File( path ).isFile();
}

/* (non-Javadoc)
 * @see org.jpws.pwslib.global.ApplicationAdapter#renameFile(java.lang.String,java.lang.String)
 */
public boolean renameFile ( String path, String newPath ) throws IOException
{
//   return false;
   return new File( path ).renameTo( new File( newPath) );
}



public void lockFileAccess ( String path ) throws IOException
{
   FileInputStream input;
   
   // look if file is already listed
   if ( filesMap.containsKey( path ) )
      return;
   
   // insert entry in files registry
   input = new FileInputStream( path );
   input.getChannel().lock( 0L, Long.MAX_VALUE, true );
   filesMap.put( path, input );

   Log.log( 7, "(DefaultFilesystemAdapter) OS-locking file: ".concat( path ) );
}

public void unlockFileAccess ( String path ) throws IOException
{
   FileInputStream input;
   
   // look if file is already listed
   if ( (input = (FileInputStream)filesMap.get( path )) == null )
      return;
   
   // unlock and remove entry
   input.close();
   filesMap.remove( path );

   Log.log( 7, "(DefaultFilesystemAdapter) OS-unlocking file: ".concat( path ) );
}

public boolean isLockedFile ( String path ) 
{
   return filesMap.containsKey( path );
}

public String separator ()
{
   return File.separator;
}

/** Returns <b>null</b> if path is <b>null</b>, empty string if path
 *  has no parent (directory) part, or parent directory (including separator
 *  sign) otherwise.
 *   
 * @param path file path in IO-context
 * @return directory name
 * @since 2-1-0 
 */
private String directoryPart ( String path )
{
   String sep, result;
   int index;
   
   if ( path == null )
      return null;
   
   sep = separator();
   index = path.lastIndexOf( sep );
   result = index == -1 ? "" : path.substring( 0, index+1 ); 
   return result;
}

public String[] list ( String trunk, String trail, boolean recurse ) throws IOException
{
//   return null;
   
   List list = new ArrayList();
   String dir, result[];
   
//   System.out.println( "-- FileSystemAdapter: listing files: [" + trunk + "]" );
   if ( separator().equals("\\") )
   {
      trunk = Util.substituteText( trunk, "/", "\\" );
      trail = Util.substituteText( trail, "/", "\\" );
   }
   
   if ( trunk == null )
      throw new NullPointerException();
   if ( trail == null )
      trail = "";
   
   if ( trunk.length() == 0 )
      return new String[0];

   if ( (dir = directoryPart( trunk )).length() == 0 )
      dir = System.getProperty( "user.dir" );
   
   analyseDirectory( dir, list, trunk, trail, recurse );
   
   result = (String[]) list.toArray( new String[ list.size() ] );
   return result;
}

/** Steps through the files of a single directory and adds matching
 * hits to the resulting file list. Recurses into subdirectories if
 * option is set.
 * 
 * @param dir path of directory to analyse
 * @param resulting resulting file list (matching hits)
 * @param trunk criterion (leading)
 * @param trail criterion (trailing)
 * @param recurse whether subdirectories are recursed
 * @since 2-1-0 
 */
private void analyseDirectory ( String dir, List resulting, 
      String trunk, String trail, boolean recurse )
{
   ArrayList subDirs;
   String file, files[], sep;
   Iterator it;
   int i;
   
//   System.out.println( "-- FileSystemAdapter: analysing directory: [" + dir + "]" );

   if ( dir == null || (files = new File( dir ).list()) == null || files.length == 0 )
      return;
   
   subDirs = new ArrayList();
   sep = separator();
   if ( !dir.endsWith( sep ) )
      dir = dir.concat( sep );
   
   // investigate parameter directory (to results)
   // take note of subdirectories
   for ( i = 0; i < files.length; i++ )
   {
      file = dir + files[ i ];
      if ( new File( file ).isDirectory() )
         subDirs.add( file );
      else if ( file.startsWith( trunk ) && file.endsWith( trail ) )
      {
         resulting.add( Util.substituteText( file, "\\", "/" ) );
//         System.out.println( "-- FileSystemAdapter: listed matching file:  [" + file + "]" );
      }
   }
   
   // recurse into subdirectories
   if ( recurse )
   for ( it = subDirs.iterator(); it.hasNext(); )
      analyseDirectory( (String)it.next(), resulting, trunk, trail, true );
}

/* (non-Javadoc)
 * @see org.jpws.pwslib.global.ApplicationAdapter#canWrite()
 */
public boolean canWrite ( String path )
{
   File f;
   
   // default value for this medium 
   if ( path == null )
      return true;
   
   f = new File( path );
   return f.exists() ? f.canWrite() : true;
}

/* (non-Javadoc)
 * @see org.jpws.pwslib.global.ApplicationAdapter#canRead()
 */
public boolean canRead ( String path ) throws IOException
{
   return new File( path ).canRead();
}

/* (non-Javadoc)
 * @see org.jpws.pwslib.global.ApplicationAdapter#canDelete()
 */
public boolean canDelete ( String path )
{
   return canWrite( path );
}

public long getFileLength ( String path )
{
   return new File( path ).length();
}

public long getModifiedTime ( String path ) throws IOException
{
   return new File( path ).lastModified();
}

/** An object equals this adapter if it is an instance of 
 *  <code>DefaultFilesystemAdapter</code>.
 *  @since 0-3-0
 */
public boolean equals ( Object obj )
{
   return obj != null && obj instanceof DefaultFilesystemAdapter;
}

/** Hashcode complying to <code>equals()</code>.
 * @since 0-3-0
 */
public int hashCode ()
{
   return classID;
}

public URL getUrl ( String filepath ) throws IOException
{
   URL url;
   
   url = Util.makeFileURL( filepath );
   return url;
}

private static class OurOutputStream extends FileOutputStream
{
   /** if true a file lock is to be installed after this stream has closed. */
   private boolean afterLock;
   private String filepath;
   
   /**
    * @param path name of the file
    * @param locked whether a file lock is currently installed on the given file
    * @throws FileNotFoundException for file creation problems
    * @throws IOException for locking problems
    */
   public OurOutputStream ( String path, boolean locked ) throws IOException
   {
      super( path );
      afterLock = locked;
      filepath = path;
      if ( locked )
         instance.unlockFileAccess( path );
   }

   public void close () throws IOException
   {
      super.close();
      
      if ( afterLock )
         instance.lockFileAccess( filepath );
   }

   
}

public boolean setModifiedTime ( String path, long time ) throws IOException
{
   return new File( path ).setLastModified( time );
}

}
