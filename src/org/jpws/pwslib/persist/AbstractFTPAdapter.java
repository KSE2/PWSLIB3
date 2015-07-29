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

import it.sauronsoftware.ftp4j.FTPAbortedException;
import it.sauronsoftware.ftp4j.FTPClient;
import it.sauronsoftware.ftp4j.FTPDataTransferException;
import it.sauronsoftware.ftp4j.FTPException;
import it.sauronsoftware.ftp4j.FTPFile;
import it.sauronsoftware.ftp4j.FTPIllegalReplyException;
import it.sauronsoftware.ftp4j.FTPListParseException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.Hashtable;

import org.jpws.pwslib.data.PwsPassphrase;
import org.jpws.pwslib.exception.InputInterruptedException;
import org.jpws.pwslib.exception.LoginFailureException;
import org.jpws.pwslib.global.Log;


/**
 * Implements a straight forward <code>ApplicationAdapter</code> for addressing
 * FTP protocol files, based on the <code>java.net</code> package and <code>
 * sun.net.ftp.FtpClient</code>.
 *  
 *  @since 0-3-0
 */
public abstract class AbstractFTPAdapter implements ApplicationAdapter
{
   protected static int classID = 33;
   protected static Hashtable<String, PwsPassphrase> logins = new Hashtable<String, PwsPassphrase>();
   protected static Hashtable<URL, FtpSession> sessions = new Hashtable<URL, FtpSession>(); 
   

/**
 * Constructs an instance.
 */
public AbstractFTPAdapter () {
}

/** Puts a login entry of the form "user:password" into the internal library
 *  by key of the domain notation. */
protected static void putLoginEntry ( String domain, String login ) {
   if ( domain == null | login == null )
      throw new NullPointerException();
   
   PwsPassphrase pass = new PwsPassphrase( login );
   logins.put( domain, pass );
}

/** Retrieves a login entry from the internal library by key of the domain 
 *  notation.
 * 
 *  @return login entry of the form "user:password" or <b>null</b> if unknown
 */
protected static String getLoginEntry ( String domain ) {
   if ( domain == null )
      throw new NullPointerException();

   PwsPassphrase pass = (PwsPassphrase) logins.get( domain );
   return pass == null ? null : pass.getString();
}

/** Probes the given FTP-Session and returns whether it is alive.
 *   
 * @param ses <code>FtpSession</code>
 * @return boolean true == alive, false == dead
 */
private boolean sessionAlive (FtpSession ses) {
	try {
		ses.testConnection();
//		Log.debug(8, "(FTP-Adapter.sessionAlive) test session OK! :"+ ses.getUrl());
		return true;
	} catch (Exception e) {
		e.printStackTrace();
		Log.debug(8, "(FTP-Adapter.sessionAlive) found test session not alive! :"+ ses.getUrl());
		return false;
	}
}

/** Retrieves or creates a FTP-session for the given URL. The returned session
 * may be in an unconnected state.
 * 
 * @param url URL - url with FTP protocol
 * @return <code>FtpSession</code>
 * @throws MalformedURLException
 */
protected FtpSession getFtpSession (URL url) throws MalformedURLException {
	FtpSession ses1 = new FtpSession(url);
	URL url1 = ses1.getUrl();
	
	// look for existing FTP session
	FtpSession ses = sessions.get(url1);
	if (ses == null || !sessionAlive(ses)) {
		// create new FTP session in map
		ses = ses1;
		sessions.put(url1, ses);
	}
	return ses;
}

/** Retrieves or creates a FTP-session for the given URL and returns it 
 * connected. If the session cannot connect to the host, an exception is thrown.
 * 
 * @param url URL - url with FTP protocol
 * @return <code>FtpSession</code>
 * @throws IOException 
 */
protected FtpSession getConnectedSession (URL url) throws IOException {
	FtpSession ses = getFtpSession(url);
	ses.connect();
	return ses;
}

/** Removes a login entry from the internal library by key of the domain 
 *  notation.
 */
protected static void removeLoginEntry ( String domain )
{
   if ( domain == null )
      throw new NullPointerException();

   logins.remove( domain );
}

@Override
public InputStream getInputStream ( String path ) throws IOException
{
	return getConnected(path).getInputStream();
}

private URLConnection getConnected ( String path ) throws IOException
{
   URLConnection urlCon;
   URL url;
   String login, domain, prot, hstr;
   int attempt, port;

   url = new URL( path );
   domain = url.getHost();
   prot = url.getProtocol();
   port = url.getPort();
   login = getLoginEntry( domain );
   attempt = login == null ? 0 : 1;
   
   while ( true )
   {
      switch ( attempt )  {
      
      case 0 :
         // first attempt plain connection (without login)
         try {
            urlCon = url.openConnection();
            urlCon.setAllowUserInteraction( true );
            Log.debug(5, "--- (FTP-Adapter) Connecting to domain (no-login): " + url.toString() );      
            urlCon.connect();
            return urlCon;
            
         } catch ( Exception e ) {
            attempt++;
         }
         break;

      case 1 :
         // second attempt with user login
         // get domain login from subclass (e.g. user input)
         if ( login == null ) {
        	login = getUserLogin( domain );
            if ( login == null )
               throw new InputInterruptedException();
            if ( login.equals("") )
               throw new ConnectException( "login not supplied" );

            putLoginEntry( domain, login );
         }

         try {
        	String po = port == -1 ? "" : ":" + port; 
            hstr = prot + "://" + login + "@" + domain + po + "/" + url.getFile();
//            hstr = "ftp://" + login + "@" + domain + ":21/" + url.getFile();
            url = new URL( hstr );
            Log.debug(5, "--- (FTP) Connecting to domain (login): " + url.toString() );   
            urlCon = url.openConnection();
            urlCon.setAllowUserInteraction( true );
            urlCon.connect();
            return urlCon;
            
         } catch ( ConnectException e2 ) {
            removeLoginEntry( domain );
            throw new LoginFailureException( "FTP login failure: ".concat(domain) );

         } catch ( IOException e3 ) {
            removeLoginEntry( domain );
            throw e3;
         }
      }
   }
}

/** Subclasses supply user login data for a requested domain name.
 *  The format of the result must be "user:password". The convention is
 *  that a return value <b>null</b> indicates a user-cancel event while an empty 
 *  string is an empty data operation request (which will lead to a connection
 *  exception thrown).
 * 
 * @param domain
 * @return String formatted user login data
 */
public abstract String getUserLogin ( String domain );


@Override
public OutputStream getOutputStream ( String path ) throws IOException
{
   return getConnected( path ).getOutputStream();
}

@Override
public String getName ()
{
   return "FTP File Locations";
}

@Override
public int getType ()
{
   return INTERNET;
}

@Override
public boolean deleteFile ( String path ) throws IOException
{
   URL url = new URL(path);
   FtpSession ftp = getConnectedSession(url);
   ftp.deleteFile( url.getPath() );
   
   Log.debug( 5, "--- (FTP-Adapter) Removed file [" + url.toString() + "]" );      
   return true;
}

@Override
public boolean existsFile ( String path ) throws IOException
{
	   URL url = new URL(path);
	   FtpSession ftp = getConnectedSession(url);
	   boolean exists = ftp.exists( url.getPath() );
	   
	   Log.debug( 5, "--- (FTP-Adapter) Exists file [" + url.toString() + "] = " + exists );      
	   return exists;

//   try {
//	   InputStream in = getInputStream(path);
//	   boolean check = in != null;
//	   if ( check ) {
//		   in.close();
//	   }
//	   return check;
//      
//   } catch (FileNotFoundException e) {
//      return false;
//   }
}

@Override
public boolean renameFile ( String path, String newPath ) throws IOException
{
   String domain, login;
   
   URL url = new URL( path );
   URL url2 = new URL( newPath );
   domain = url.getHost();
   if (!domain.equals(url2.getHost()))
	   throw new IOException("host references ambiguous");

   FtpSession ftp = getConnectedSession(url);
   ftp.rename( url.getPath(), url2.getPath() );
   
   Log.debug( 5, "--- (FTP-Adapter) Renamed file [" + url.toString() + 
            "] to [" + url2.toString() + "]" );      
   return true;
}

@Override
public void lockFileAccess ( String path ) throws IOException
{
   // TODO Auto-generated method stub
   
}

@Override
public void unlockFileAccess ( String path ) throws IOException
{
   // TODO Auto-generated method stub
   
}


@Override
public String[] list ( String trunk, String trail, boolean recurse ) throws IOException
{
   FtpSession ftp;
   URL url;
   String domain, path, prot;
   
   // cannot perform recurse into subdirs
//   if ( recurse )
//      return null;

   // assemble
   url = new URL( trunk );
   domain = url.getHost();
   path = url.getPath();
   prot = trunk.substring( 0, trunk.indexOf( domain ) );
//   base = trunk.substring( 0, trunk.indexOf( domain ) + domain.length() );
   
   // connect to host
   ftp = getConnectedSession(url);

   // download file name list
   String[] names = ftp.fileList(path, recurse);

   // adjust file name list
   if (names != null && names.length > 0) {
	   // filter list for parameter ending, if opted
	   if ( trail != null ) {
		   ArrayList<String>list = new ArrayList<String>();
		   for ( String na : names ) {
		      if ( na.endsWith(trail) )
		         list.add( na );
		   }
		   names = list.toArray( new String[list.size()] );
	   }
	   
	   // prepend file names with domain url path
	   String prefix = ftp.getUrl().toString();
	   int i = 0;
	   for ( String na : names ) {
	      names[i++] = prefix.concat( na );
	   }
   }
   
//   ftp.echoStr(names);
   return names;
}


@Override
public String separator ()
{
   return "/";
}

@Override
public boolean canWrite ( String path )
{
   return true;
}

@Override
public boolean canRead ( String path ) throws IOException
{
   return existsFile( path );
}

@Override
public boolean canDelete ( String path )
{
   return true;
}

@Override
public long getFileLength ( String path ) throws IOException {
   URL url = new URL(path);
   FtpSession ftp = getConnectedSession(url);
	   
   long time = ftp.getFileSize( url.getPath() ); 
   return time;
}

@Override
public long getModifiedTime ( String path ) throws IOException
{
   long time = 0;
   URL url = new URL(path);

   FtpSession ftp = getConnectedSession(url);
   
   try { 
	   time = ftp.getFileTime( url.getPath() ); 
   } catch ( IOException e ) {
   }

   return time;
}


@Override
public URL getUrl ( String filepath ) throws IOException
{
   URL url;
   String hstr;
   
   url = new URL( filepath );
   hstr = url.getProtocol();
   if ( !hstr.equals( "ftp" ))
      throw new MalformedURLException( "FTP adapter error: unsupported protocol: ".concat( hstr ) );
   return url;
}

/** An object equals this adapter if it is an instance of <code>AbstractFTPAdapter
 *  </code>.
 */
@Override
public boolean equals ( Object obj )
{
   return obj != null && obj instanceof AbstractFTPAdapter;
}

@Override
public int hashCode ()
{
   return classID;
}

// *************** INNER CLASSES *********************

protected class FtpSession {
	FTPClient client = new FTPClient();
	URL url;
	String host;
	String username;
	String prot;
	PwsPassphrase password;
	
	/** Creates a new FTP-session for the given URL notation.
	 * 
	 * @param url String url to host
	 * @throws MalformedURLException if host name is malformed
	 * @throws IllegalArgumentException if host name is empty
	 * @throws NullPointerException
	 */
	public FtpSession (String url) throws MalformedURLException {
		this(new URL(url));
	}
	
	/** Creates a new FTP-session from the given URL.
	 *  
	 * @param url URL - url with FTP, FTPS, FTPES protocol
	 * @throws IllegalArgumentException if wrong protocol or no domain supplied
	 * @throws NullPointerException
	 */
	public FtpSession (URL url) {
		prot = url.getProtocol();
		host = url.getHost();
		if (host == null || host == "")
			throw new IllegalArgumentException("empty host domain");
		
		try {
			this.url = new URL(prot, host, "");
		} catch (MalformedURLException e) {
		}

		if (prot.equals("ftp")) {
		} else if (prot.equals("ftps")) {
			client.setSecurity(FTPClient.SECURITY_FTPS);
		} else if (prot.equals("ftpes")) {
			client.setSecurity(FTPClient.SECURITY_FTPES);
		} else
			throw new IllegalArgumentException("illegal protocol: ".concat(prot));
		
		Log.log(10, "(FTP-Session) create new instance: " + this.url);
	}

	/** Tests whether this session is alive and throws an exception if not.
	 * 
	 * @throws IllegalStateException
	 * @throws IOException
	 * @throws FTPIllegalReplyException
	 * @throws FTPException
	 */
	public void testConnection() throws IllegalStateException, IOException,
		FTPIllegalReplyException, FTPException {
		client.noop();
	}

	/** Returns the URL of the host domain.
	 * 
	 * @return URL
	 */
	public URL getUrl () {
		return url;
	}
	
	public String getHost () {
		return host;
	}
	
	private void echoStr (String[] arr) {
		if (Log.getDebugLevel() > 4) {
			for (String s : arr) {
				Log.debug(5, "(FTP-Session.echo) ".concat(s));
			}
		}
	}
	
	public void connect () throws IOException {
		if (isConnected()) return;
		String input = null;

		try {
			// connect to target host
			if (!client.isConnected()) {
				try {
					Log.log(8, "(FTP-Session.connect) trying to CONNECT to ".concat(host));
					String[] echo = client.connect(host);
					echoStr(echo);
				} catch (IllegalStateException e) {
					// already connected
				}
			}
			
			// login to target host
			if (username == null) {
				// obtain a user login value
				input = getLoginEntry(host);
				if (input == null) {
					input = getUserLogin(host);
				}
				if (input == null)
					throw new IOException("user operation cancel");
				int i = input.indexOf(':');
				if (i == -1)
					throw new IOException("invalid login data (formal)");
				
				putLoginEntry(host, input);
				username = input.substring(0, i);
				password = new PwsPassphrase(input.substring(i+1, input.length()));
				Log.debug(5, "(FTP-Session.connect) user login data supplied: u=" + username +
						", p=" + password.getString());
			}
			Log.log(8, "(FTP-Session.connect) trying to LOGIN to ".concat(host));
			client.login(username, password.getString());
			
		} catch (FTPIllegalReplyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new IOException(e);
		} catch (FTPException e) {
			// TODO Auto-generated catch block
			username = null;
			password = null;
			removeLoginEntry(host);
			e.printStackTrace();
			throw new IOException(e);
		}
	}
	
	public boolean isConnected () {
		return client.isConnected() && client.isAuthenticated();
	}
	
	public long getFileTime (String path) throws IOException {
		try {
			long time = client.modifiedDate(path).getTime();
			Log.debug(10, "(FTP-Session) get file time [" + path + "] == " + time);
			return time;
			
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new IOException(e);
		} catch (FTPIllegalReplyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new IOException(e);
		} catch (FTPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new IOException(e);
		}
	}

	/** Returns the size of the given file or -1 if the file does not exist.
	 *   
	 * @param path String file path
	 * @return long file size or -1
	 * @throws IOException
	 */
	public long getFileSize (String path) throws IOException {
		try {
			long size = client.fileSize(path);
			Log.debug(10, "(FTP-Session) get file size [" + path + "] == " + size);
			return size;
			
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new IOException(e);
		} catch (FTPIllegalReplyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new IOException(e);
		} catch (FTPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new IOException(e);
		}
	}

	public void rename (String path1, String path2)  throws IOException {
		try {
			client.rename(path1, path2);
			Log.debug(10, "(FTP-Session) renamed files [" + path1 + "] ==> " + path2);

		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new IOException(e);
		} catch (FTPIllegalReplyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new IOException(e);
		} catch (FTPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new IOException(e);
		}
	}
	
	public void deleteFile (String path) throws IOException {
		try {
			client.deleteFile(path);
			Log.debug(10, "(FTP-Session) removed file [" + path + "]");
	
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new IOException(e);
		} catch (FTPIllegalReplyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new IOException(e);
		} catch (FTPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new IOException(e);
		}
	}

	public boolean exists (String path)  throws IOException {
		boolean exist = false;
		
		try {
			FTPFile[] farr = client.list(path);
			exist = farr != null && farr.length > 0;
			
//			for (FTPFile file : farr) {
//				Log.debug(10, "(FTP-Session.exists) FILE-VALUE : [" + file.getName() + "] "
//						+ (file.getType() == FTPFile.TYPE_DIRECTORY ? 'D' : 'F'));
//			}
			
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new IOException(e);
		} catch (FTPIllegalReplyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new IOException(e);
		} catch (FTPException e) {
			// if other than file-not-found then throw exception
			if (e.getCode() != 450) {
				e.printStackTrace();
				throw new IOException(e);
			}
		} catch (FTPDataTransferException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new IOException(e);
		} catch (FTPAbortedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new IOException(e);
		} catch (FTPListParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new IOException(e);
		}

		Log.debug(10, "(FTP-Session) file exists [" + path + "] == " + exist);
		return exist;
	}

	/** Returns the list of all full domain paths of files which start with the 
	 * given text. This does not include directories!
	 * 
	 * @param path String starting value of file list (may be a directory name
	 *             or a trunk of a file name).
	 * @param recurse boolean whether results should include sub-directories
	 * @return array of String, each giving a full file path
	 */
	public String[] fileList (String path, boolean recurse) throws IOException {
		Log.log(10, "(FTP-Session) file list for search string == [" + path + "]");
	
		try {
			FTPFile[] files = new FTPFile[0];
			boolean isDirectory = false;
			try {
				files = client.list(path);
				isDirectory = files.length > 1;
			} catch (FTPException e) {
			}
			
			if (!isDirectory) {
				files = client.list(path.concat("*"));
				
			} else if (recurse ) {
				// TODO recurse into subdirs
			}

			// filter out dirs
			ArrayList<String> flist = new ArrayList<String>();
			for (FTPFile f : files) {
				if (f.getType() == FTPFile.TYPE_FILE) {
					flist.add(f.getName());
				}
			}
			
			String[] result = flist.toArray(new String[flist.size()]);
			echoStr(result);
			return result;
			
		} catch (IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new IOException(e);
		} catch (FTPIllegalReplyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new IOException(e);
		} catch (FTPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new IOException(e);
		} catch (FTPDataTransferException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new IOException(e);
		} catch (FTPAbortedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new IOException(e);
		} catch (FTPListParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new IOException(e);
		}
	}

}

}
