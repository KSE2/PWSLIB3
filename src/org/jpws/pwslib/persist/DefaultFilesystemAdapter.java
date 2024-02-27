/*
 *  File: DefaultFilesystemAdapter.java
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

import kse.utilclass.misc.Log;
import kse.utilclass.misc.Util;

/**
 * Implements a straight forward <code>ApplicationAdapter</code> for the
 * local file system, based on the java.io package. This is the default 
 * standard application installed by the <code>Global.init</code> function.
 */

public class DefaultFilesystemAdapter implements ApplicationAdapter
{
   protected static int classID = 11;
   protected static DefaultFilesystemAdapter instance = new DefaultFilesystemAdapter();

   private HashMap<String, FileInputStream> filesMap = new HashMap<String, FileInputStream>(); 
   
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

@Override
public InputStream getInputStream ( String path ) throws IOException
{
   return new FileInputStream( path );
}

@Override
public OutputStream getOutputStream ( String path ) throws IOException
{
   return new OurOutputStream( path, isLockedFile( path ) );
}

@Override
public String getName ()
{
   return "Local Files";
}

@Override
public int getType ()
{
   return FILESYSTEM;
}

@Override
public boolean deleteFile ( String path ) throws IOException
{
   return new File( path ).delete();
}

@Override
public boolean existsFile ( String path ) throws IOException
{
   return new File( path ).isFile();
}

@Override
public boolean renameFile ( String path, String newPath ) throws IOException
{
//   return false;
   return new File( path ).renameTo( new File( newPath) );
}

@Override
public void lockFileAccess ( String path ) throws IOException
{
   // look if file is already listed
   if ( filesMap.containsKey( path ) ) return;
   
   // insert entry in files registry
   FileInputStream input = new FileInputStream( path );
   input.getChannel().lock( 0L, Long.MAX_VALUE, true );
   filesMap.put( path, input );

   Log.log( 7, "(DefaultFilesystemAdapter) OS-locking file: ".concat( path ) );
}

@Override
public void unlockFileAccess ( String path ) throws IOException
{
   // look if file is already listed
   FileInputStream input = (FileInputStream)filesMap.get( path );
   if ( input == null ) return;
   
   // unlock and remove entry
   input.close();
   filesMap.remove( path );

   Log.log( 7, "(DefaultFilesystemAdapter) OS-unlocking file: ".concat( path ) );
}

public boolean isLockedFile ( String path ) 
{
   return filesMap.containsKey( path );
}

@Override
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
 */
private String directoryPart ( String path )
{
   if ( path == null ) return null;
   
   String sep = separator();
   int index = path.lastIndexOf( sep );
   String result = index == -1 ? "" : path.substring( 0, index+1 ); 
   return result;
}

@Override
public String[] list ( String trunk, String trail, boolean recurse ) throws IOException
{
//   return null;
   
   List<String> list = new ArrayList<String>();
   String dir, result[];
   
//   System.out.println( "-- FileSystemAdapter: listing files: [" + trunk + "]" );
   if ( separator().equals("\\") ) {
      trunk = Util.substituteText( trunk, "/", "\\" );
      trail = Util.substituteText( trail, "/", "\\" );
   }
   
   if ( trunk == null ) {
      throw new NullPointerException();
   }
   
   if ( trail == null ) {
      trail = "";
   }
   
   if ( trunk.length() == 0 ) {
      return new String[0];
   }

   if ( (dir = directoryPart( trunk )).length() == 0 ) {
      dir = System.getProperty( "user.dir" );
   }
   
   analyseDirectory( dir, list, trunk, trail, recurse );
   
   result = list.toArray( new String[list.size()] );
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
 */
private void analyseDirectory ( String dir, List<String> resulting, 
      String trunk, String trail, boolean recurse )
{
   ArrayList<String> subDirs = new ArrayList<String>();
   String file, files[], sep;
   
//   System.out.println( "-- FileSystemAdapter: analysing directory: [" + dir + "]" );

   if ( dir == null || (files = new File( dir ).list()) == null || files.length == 0 )
      return;
   
   sep = separator();
   if ( !dir.endsWith( sep ) ) {
      dir = dir.concat( sep );
   }
   
   // investigate parameter directory (to results)
   // take note of subdirectories
   for ( int i = 0; i < files.length; i++ ) {
      file = dir + files[ i ];
      if ( new File( file ).isDirectory() ) {
         subDirs.add( file );
      } else if ( file.startsWith( trunk ) && file.endsWith( trail ) ) {
         resulting.add( Util.substituteText( file, "\\", "/" ) );
//         System.out.println( "-- FileSystemAdapter: listed matching file:  [" + file + "]" );
      }
   }
   
   // recurse into subdirectories
   if ( recurse ) {
	  for ( Iterator<String> it = subDirs.iterator(); it.hasNext(); ) {
         analyseDirectory( (String)it.next(), resulting, trunk, trail, true );
	  }
   }
}

@Override
public boolean canWrite ( String path )
{
   // default value for this medium 
   if ( path == null ) return true;
   
   File f = new File( path );
   return f.exists() ? f.canWrite() : true;
}

@Override
public boolean canRead ( String path ) throws IOException
{
   return new File( path ).canRead();
}

@Override
public boolean canDelete ( String path )
{
   return canWrite( path );
}

@Override
public long getFileLength ( String path )
{
   return new File( path ).length();
}

@Override
public long getModifiedTime ( String path ) throws IOException
{
   return new File( path ).lastModified();
}

/** An object equals this adapter if it is an instance of 
 *  <code>DefaultFilesystemAdapter</code>.
 */
@Override
public boolean equals ( Object obj )
{
   return obj != null && obj instanceof DefaultFilesystemAdapter;
}

/** Hashcode complying to <code>equals()</code>.
 */
@Override
public int hashCode ()
{
   return classID;
}

@Override
public URL getUrl ( String filepath ) throws IOException
{
   URL url = Util.makeFileURL( filepath );
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

   @Override
   public void close () throws IOException
   {
      super.close();

      if ( afterLock )
         instance.lockFileAccess( filepath );
   }
}

@Override
public boolean setModifiedTime ( String path, long time ) throws IOException
{
   return new File( path ).setLastModified( time );
}

}
