/*
 *  ApplicationAdapter in org.jpws.pwslib.global
 *  file: ApplicationAdapter.java
 * 
 *  Project JPasswords
 *  @author Wolfgang Keller
 *  Created 05.08.2004
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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;

import org.jpws.pwslib.global.Global;

/**
 *  Interface for functions required from the context of a pluggable application.
 *  Presently the purpose of the interface consists in providing an IO-context
 *  for input and output streams for persistent files. 
 *  Note that the syntax of file path specifications is open and solely dependent
 *  on the conventions posed by an implementing class.
 * 
 *  <p>The backend library implements a <u>standard application adapter</u> for 
 *  the local file system (which is automatically loaded), namely 
 *  {@link DefaultFilesystemAdapter}. The library always expects at least one 
 *  adapter being loaded and can serve an unlimited number of user defined adapter 
 *  implementations. Loading of adapters occurs through the static class 
 *  {@link Global}.  
 */
public interface ApplicationAdapter 
{
   /** Adapter-type for a user addressable file system (e.g. the local file 
    *  system).
    */
   static final int FILESYSTEM = 0;

   /** Adapter-type for an Internet based IO-context.
   */   
   static final int INTERNET = 1;
   
   /** Adapter-type for any other application specific IO-context.
    */
   static final int DATABASE = 2;
   
/** Renders an <code>InputStream</code> for a file identified by the
 *  parameter <code>path</code> valid within the IO-context of this 
 *  application. 
 * 
 * @param path file identification string
 * @return <code>java.io.InputStream</code>
 * @throws IOException
 */   
InputStream getInputStream ( String path ) throws IOException;

/** Renders an <code>OutputStream</code> for a file identified by the
 *  parameter <code>path</code> valid within the IO-context of this 
 *  application.
 * 
 * @param path file identification string
 * @return <code>java.io.OutputStream</code>
 * @throws IOException
 */   
OutputStream getOutputStream ( String path ) throws IOException;

/** Returns a list of full file paths from the directory system of this 
 * IO-context which all start with the text of <code>trunk</code>.
 * <code>trail</code> is an optional additional selection criterion 
 * determining the file path ending. Directories are not included
 * in the result list.
 * 
 * @param trunk starting text of resulting file paths; if the path name
 *        of a directory is entered, it must end with a separator sign.
 *        (The behaviour if parameter is empty is context specific hence
 *        undefined)
 * @param trail if not <b>null</b> ending text of resulting file paths
 * @param recurse if <b>true</b> files of subdirectories are included
 * @return <code>String</code> array of file paths in IO-context
 *         or <b>null</b> indicating this function is not supported
 * @throws IOException
 * @since 2-1-0
 */
String[] list ( String trunk, String trail, boolean recurse ) throws IOException;

/** Attempts to rename or move a specified file in the context of the 
 * application. Note that moving of a file is not necessarily supported
 * by an implementation or may be restricted as to valid destinations.
 * 
 * @param path an existing file with write rights
 * @param newPath the new name or location of the file
 * @return <b>true</b> if an only if the operation was successful
 * @throws IOException
 */
boolean renameFile ( String path, String newPath ) throws IOException;

/** Attempts to delete a specified file in the context of the application.
 *  
 * @param path an existing file with write rights
 * @return <b>true</b> if an only if the file does not exist after termination
 *          of this method
 * @throws IOException
 */
boolean deleteFile ( String path ) throws IOException;

/** Determines whether there exists a specific file in the context of the 
 *  application.
 * 
 * @param path a file path
 * @return <b>true</b> if and only if the given file exists
 * @throws IOException
 */
boolean existsFile ( String path ) throws IOException;

/** Attempts to block IO-access to a specific file for other executable
 * processes.
 * 
 * @param path String single file specification
 * @throws IOException
 */
void lockFileAccess ( String path )  throws IOException;

/** Attempts to unblock IO-access to a specific file in this context
 * (which was blocked before by method <code>lockFileAccess()</code>).
 * 
 * @param path String single file specification
 * @throws IOException
 */
void unlockFileAccess ( String path )  throws IOException; 

/** The application name as referred to in user interface.
 *  This must not be null or empty, otherwise the application
 *  will not get registered!
 */ 
String getName ();


/** Returns the application type.
 * 
 * @return one of FILESYSTEM, DATABASE or INTERNET
 */
int getType ();

/**
 * Whether this application's IO-context allows to write the specified file. 
 */
boolean canWrite ( String path ) throws IOException;

/**
 * Whether this application's IO-context allows to read the specified file.
 * This normally incorporates test for existence of a file, but may extend to 
 * other criteria.  
 * @since 0-3-0
 */
boolean canRead ( String path ) throws IOException;

/**
 * Whether this application's IO-context allows to delete the specified file. 
 * @since 0-3-0
 */
boolean canDelete ( String path );

/** Returns the time of last modification of the specified file.
 * 
 * @param path file path
 * @return time value in milliseconds since epoch
 * @throws IOException
 * @since 0-3-0
 */
long getModifiedTime ( String path ) throws IOException;

/** Attempts to set the "last modified" time marker for the parameter
 * file on the external IO context. 
 * @param path file path
 * @param time long Epoch time millis 
 * @return boolean <b>true</b> if and only if this operation was successful
 * @throws IOException
 */
boolean setModifiedTime ( String path, long time ) throws IOException;

/** Returns the total length in Bytes of the specified file
 * or -1 if this information is not available.
 * 
 * @param path file path
 * @return length in Bytes
 * @throws IOException
 * @since 2-1-0
 */
long getFileLength ( String path ) throws IOException;

/** The separating character of path-name elements in the convention
 * of this IO-context. 
 * @since 2-1-0 
 */
String separator ();

/** Returns an URL descriptor specifying a file in this application context 
 * identified by the parameter path string. It is assumed the naming is canonised.
 * Adapters which cannot describe their files as URL may return <b>null</b>.
 * 
 * @return URL file descriptor or <b>null</b>
 * @throws IOException
 */  
URL getUrl ( String filepath ) throws IOException;

}
