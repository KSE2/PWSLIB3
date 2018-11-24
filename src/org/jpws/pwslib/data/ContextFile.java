/*
 *  File: ContextFile.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 13.02.2007
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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URL;

import org.jpws.pwslib.exception.ApplicationFailureException;
import org.jpws.pwslib.global.Global;
import org.jpws.pwslib.global.Util;
import org.jpws.pwslib.persist.ApplicationAdapter;
import org.jpws.pwslib.persist.DefaultFilesystemAdapter;
import org.jpws.pwslib.persist.StreamFactory;

/**
 * A ContextFile is the combination of <code>ApplicationAdapter</code> and
 * a filepath. This two-tuple is meant to define an unequivocal file in the 
 * context of a program using the PWSLIB, giving the freedom to abstract from 
 * different resource media. Abbreviated constructors are available for 
 * the local file system and the system's standard application adapter, for the
 * case this should be different.
 * <p>A ContextFile always has meaningful settings for adapter and filepath. 
 * These values cannot be modified after creation of an instance. 
 *  
 */
public class ContextFile
{
   private ApplicationAdapter    adapter;
   private String                filepath;
   private URL                   url;
   
   private long                  fileTime;
   private long                  fileLength;
   private boolean               hasRefreshed;


/** Creates a context file from the local file system.
 * 
 * @param file <code>File</code>
 */
public ContextFile ( File file ) 
{
	this(DefaultFilesystemAdapter.get(), file.getAbsolutePath());
}
   
/** Creates a context file from the system's standard application adapter.
 * <p><small>The standard application adapter is defined in
 *  org.jpws.pwslib.global.Global.</small>
 * 
 * @param filepath <code>String</code> file path
 */
public ContextFile ( String filepath ) 
{
	this(Global.getStandardApplication(), filepath);
}
   
/**
 *  Creates a context file with the given IO-context and file name.
 *  
 *  @param adapter <code>ApplicationAdapter</code> IO-context adapter
 *  @param filepath <code>String</code> file identifying expression in <code>adapter</code>
 *  @throws NullPointerException
 */
public ContextFile ( ApplicationAdapter adapter, String filepath )
{
   if ( adapter == null | filepath == null )
      throw new NullPointerException();

   if ( filepath.isEmpty() )
      throw new IllegalArgumentException( "filepath is empty" );
   
   this.adapter = adapter;
   this.filepath = filepath;
}

/**
 * Refreshes file related information (like modify time and length) from
 * the persistent state resource (external medium). This should be expected
 * to be a moderately expensive operation. 
 */
public void refresh () throws IOException
{
   fileTime = adapter.getModifiedTime( filepath );
   fileLength = adapter.getFileLength( filepath );
   hasRefreshed = true;
}

/**
 * Time of last modification of this file or zero if this information
 * is not available.
 * 
 * @return long time in epoch milliseconds
 */
public long modifyTime ()
{
   try {
      if ( !hasRefreshed ) {
         refresh();
      }
   } catch ( IOException e ) {
   }
   return fileTime;
}

/**
 * Total length in Bytes of this file or -1 if this information
 * is not available.
 * 
 * @return long file length in Bytes or -1
 */
public long length ()
{
   try {
      if ( !hasRefreshed ) {
         refresh();
      }
   } catch ( IOException e ) {
   }
   return fileLength;
}

/** Two <code>ContextFile</code> objects are equal if their <code>adapter</code>
 * and <code>filepath</code> settings are equal.
 * 
 * @return boolean
 */
@Override
public boolean equals ( Object obj )
{
   if ( obj == null ) return false;

   ContextFile f = (ContextFile)obj;
   return this.adapter.equals(f.adapter) && this.filepath.equals(f.filepath);
}

@Override
public int hashCode ()
{
   return adapter.hashCode() ^ filepath.hashCode();
}

/** The IO-context of this database file. 
 * 
 *  @return <code>ApplicationAdapter</code> IO-context adapter
 */
public ApplicationAdapter getAdapter ()
{
   return adapter;
}

/** Returns an URL description of this file definition if applicable
 * or <b>null</b> otherwise.
 * 
 * @return URL file descriptor or <b>null</b>
 * @throws java.net.MalformedURLException
 */  
public URL getUrl () throws IOException
{
   if ( url == null ) {
      url = adapter.getUrl( filepath );
   }
   return url;
}

/** The path expression valid in IO-context identifying this context file.
 * 
 * @return <code>String</code> file path 
 */  
public String getFilepath ()
{
   return filepath;
}

/** 
 * Returns the file name part of the file path definition of this context file.
 * 
 * @return <code>String</code> file name element 
 */  
public String getFileName ()
{
   String hstr = getFilepath();
   int i = hstr.lastIndexOf( adapter.separator() );
   if ( i > -1 ) {
      hstr = hstr.substring( i+1 );
   }
   return hstr; 
}

/** 
 * Returns the directory name part of the file path definition of this 
 * context file. The expression ends with a separator character.
 * 
 * @return <code>String</code> parent name element 
 */  
public String getFileParentName() {
   String hstr = getFilepath();
   int i = hstr.lastIndexOf( adapter.separator() );
   if ( i > -1 ) {
      hstr = hstr.substring(0, i+1 );
   }
   return hstr; 
}


/** Attempts to delete the persistent state of this context file on the 
 * external file system.
 * 
 * @return boolean <b>true</b> if and only if the file does not exist after
 *         termination of this method
 * @throws IOException
 */ 
public boolean delete () throws IOException
{
   boolean ok = adapter.deleteFile( filepath );
   if ( ok ) {
	   hasRefreshed = false;
   }
   return ok;
}

/** Attempts to rename this file to the given path expression on the external
 * medium. If the file does not exist or this operation is not permitted, 
 * <b>false</b> is returned. The file path of this file does not change by
 * this operation!
 * <p>The moving of this file to a different location may also be triggered by
 * this method, if this operation is supported by the external file system. 
 * 
 * @param newpath String new identifier of this file on external file system
 * @return boolean <b>true</b> if and only if the operation was successful 
 * @throws IOException
 */ 
public boolean renameTo ( String newpath ) throws IOException
{
   boolean ok = adapter.renameFile( filepath, newpath );
   return ok;
}

/** Whether this file has a persistent state on the external medium. 
 * 
 * @return boolean <b>true</b> if and only if the file exists external 
 * @throws IOException
 */
public boolean exists () throws IOException
{
   return adapter.existsFile( filepath );
}

/** Returns a buffered input stream from the persistent state of this file.
 * 
 * @return <code>InputStream</code>
 * @throws IOException
 * @throws ApplicationFailureException
 */
public InputStream getInputStream () throws IOException, ApplicationFailureException
{
   return StreamFactory.getInputStream( adapter, filepath );
}

/** Returns a buffered output stream for a new persistent state of this file 
 * (overwriting a previously existing content).
 * 
 * @return <code>OutputStream</code>
 * @throws IOException
 * @throws ApplicationFailureException
 */
public OutputStream getOutputStream () throws IOException, ApplicationFailureException
{
   OutputStream out = StreamFactory.getOutputStream( adapter, filepath );
   hasRefreshed = false;
   return out;
}

/** Writes the given text string as new content of this file to external medium.
 * <br>ATTENTION!! - This overwrites any previous content of the file!!
 * 
 * @param text String text content to be written to file
 * @param charset String character set to be used for text encoding
 * @throws IOException
 * @throws ApplicationFailureException
 * @throws UnsupportedEncodingException
 */
public void writeString ( String text, String charset ) 
		throws IOException, ApplicationFailureException 
{
	OutputStream out = getOutputStream();
	if ( text != null ) {
		byte[] buffer = text.getBytes(charset);
		out.write(buffer);
	}
	out.close();
}

/** Whether this file can perform creation of a new persistent state.
 * 
 *  @return boolean
 */
public boolean canWrite () throws IOException
{
   return adapter.canWrite( filepath );
}

/** Whether this file can perform reading from its persistent state. 
 * 
 *  @return boolean
 */
public boolean canRead () throws IOException
{
   return adapter.canRead( filepath );
}

/** Copies the content of this context file to the parameter context file. 
 * (This method attempts to delete the target file in case of an error condition
 *  after creating the output stream.)
 * 
 * @param target <code>ContextFile</code> file destination
 * @throws IllegalArgumentException if the target is this file
 * @throws IOException
 */
public void copyTo ( ContextFile target ) throws IOException, ApplicationFailureException
{
	// control nonsense
	if ( target.equals(this) ) 
		throw new IllegalArgumentException("copy to self");
	
   OutputStream out = null;
   InputStream in = getInputStream();
   try {
      out = target.getOutputStream();
      Util.copyStream( in, out );
      out.close();
      
   } catch ( Exception e ) {
      if ( out != null ) {
         out.close();
         try { 
        	 target.delete(); 
      	 } catch ( IOException e1 ) {
      	 }
      }
      if (e instanceof IOException) 
         throw (IOException)e;
      if (e instanceof ApplicationFailureException) 
          throw (ApplicationFailureException)e;
      if (e instanceof RuntimeException) 
          throw (RuntimeException)e;

   } finally {
      in.close();
   }
}

/** Copies this context file to the parameter file destination
 * of the same IO-context. (This method attempts to delete the 
 * target file in case of an error condition after creating
 * the output stream.)
 * 
 * @param path String target file path
 * @throws IOException
 */
public void copyTo ( String path ) throws IOException, ApplicationFailureException
{
   copyTo( new ContextFile( adapter, path ) );
}

/** Attempts to set the modify time marker for this file on the persistent medium.
 * 
 * @return boolean <b>true</b> if and only if this operation was successful
 * @throws IOException 
 */
public boolean setModifyTime ( long modifyTime ) throws IOException
{
   return adapter.setModifiedTime( filepath, modifyTime );
}

/** This file is replaced by the given data content.
 * 
 * @param data byte[]
 * @throws IOException 
 * @throws NullPointerException if parameter is null
 */
public void receiveContent (byte[] data) throws IOException {
	if (data == null)
		throw new NullPointerException("data is null");
	
	OutputStream out = getOutputStream();
	ByteArrayInputStream in = new ByteArrayInputStream(data);
	try {
		Util.transferData(in, out, 4096);
	} finally {
		out.close();
	}
}

}
