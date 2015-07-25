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

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.GregorianCalendar;
import java.util.HashMap;

import org.jpws.pwslib.data.PwsPassphrase;
import org.jpws.pwslib.exception.InputInterruptedException;
import org.jpws.pwslib.exception.LoginFailureException;
import org.jpws.pwslib.global.Log;
import org.jpws.pwslib.global.Util;

import sun.net.TelnetInputStream;
import sun.net.ftp.FtpClient;

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
   protected static HashMap logins = new HashMap(); 
   

/**
 * Constructs an instance.
 */
public AbstractFTPAdapter ()
{
}

/** Puts a login entry of the form "user:password" into the internal library
 *  by key of the domain notation. */
protected synchronized static void putLoginEntry ( String domain, String login )
{
   PwsPassphrase pass;
   
   if ( domain == null | login == null )
      throw new NullPointerException();
   
   pass = new PwsPassphrase( login );
   logins.put( domain, pass );
}

/** Retrieves a login entry from the internal library by key of the domain 
 *  notation.
 * 
 *  @return login entry of the form "user:password" or <b>null</b> if unknown
 */
protected synchronized static String getLoginEntry ( String domain )
{
   PwsPassphrase pass; 
   
   if ( domain == null )
      throw new NullPointerException();

   pass = (PwsPassphrase) logins.get( domain );
   return pass == null ? null : pass.getString();
}

/** Removes a login entry from the internal library by key of the domain 
 *  notation.*/
protected synchronized static void removeLoginEntry ( String domain )
{
   if ( domain == null )
      throw new NullPointerException();

   logins.remove( domain );
}

/* (non-Javadoc)
 * @see org.jpws.pwslib.global.ApplicationAdapter#getInputStream(java.lang.String)
 */
public InputStream getInputStream ( String path ) throws IOException
{
   return getConnected( path ).getInputStream();
}

private URLConnection getConnected ( String path ) throws IOException
{
   URLConnection urlCon;
   URL url;
   String login, domain, hstr;
   int attempt;

   url = new URL( path );
   domain = url.getHost();
   login = getLoginEntry( domain );
   attempt = login == null ? 0 : 1;
   
   while ( true )
   {
      switch ( attempt )
      {
      case 0 :
         // first attempt plain connection (without login)
         try {
            urlCon = url.openConnection();
            urlCon.setAllowUserInteraction( true );
      if ( Log.getDebugLevel() > 4 )      
      System.out.println( "--- (FTP) Connecting to domain: " + url.toString() );      
            //in = urlCon.getInputStream();
            urlCon.connect();
            return urlCon;
         }
         catch ( sun.net.ftp.FtpLoginException e )
         {
            attempt++;
         }
         break;

      case 1 :
         // second attempt with user login
         // get domain login from subclass (e.g. user input)
         if ( login == null )
         {   
            if ( (login = getUserLogin( domain )) == null )
               throw new InputInterruptedException();
            if ( login.equals("") )
               throw new ConnectException( "login not supplied" );

            putLoginEntry( domain, login );
         }

         try {
            hstr = "ftp://" + login + "@" + domain + ":21/" + url.getFile();
            url = new URL( hstr );
   if ( Log.getDebugLevel() > 4 )      
   System.out.println( "--- (FTP) Connecting to domain: " + url.toString() );   
            urlCon = url.openConnection();
            urlCon.setAllowUserInteraction( true );
            urlCon.connect();
            return urlCon;
         }
         catch ( sun.net.ftp.FtpLoginException e2 )
         {
            removeLoginEntry( domain );
            throw new LoginFailureException( "FTP login failure: ".concat(domain) );
         }
         catch ( IOException e3 )
         {
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


/* (non-Javadoc)
 * @see org.jpws.pwslib.global.ApplicationAdapter#getOutputStream(java.lang.String)
 */
public OutputStream getOutputStream ( String path ) throws IOException
{
   return getConnected( path ).getOutputStream();
}

/* (non-Javadoc)
 * @see org.jpws.pwslib.global.ApplicationAdapter#getName()
 */
public String getName ()
{
   return "FTP File Locations";
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
   OurFtpClient ftp;
   String domain, login;
   URL url;
   int i;
   
   url = new URL( path );
   domain = url.getHost();
   if ( (login = getLoginEntry( domain )) == null )
      return false;
   
   ftp = new OurFtpClient( domain );
   i = login.indexOf( ':' );
   ftp.login( login.substring( 0, i ), login.substring( i+1 ) );
   ftp.delete( url.getFile() );
   ftp.closeServer();
   if ( Log.getDebugLevel() > 4 )      
      System.out.println( "--- (FTP) Deleted file: " + url.toString() );      
   
   return true;
}

/* (non-Javadoc)
 * @see org.jpws.pwslib.global.ApplicationAdapter#existsFile(java.lang.String)
 */
public boolean existsFile ( String path ) throws IOException
{
   InputStream in;   
   boolean check;
   
   try {
      in = getConnected( path ).getInputStream();
      check = in != null;
      in.close();
      return check;
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
   OurFtpClient ftp;
   String domain, login;
   URL url, url2;
   int i;
   
   url = new URL( path );
   url2 = new URL( newPath );
   domain = url.getHost();
   if ( (login = getLoginEntry( domain )) == null )
      return false;
   
   ftp = new OurFtpClient( domain );
   i = login.indexOf( ':' );
   ftp.login( login.substring( 0, i ), login.substring( i+1 ) );
   ftp.rename( url.getFile(), url2.getFile() );
   ftp.closeServer();
   if ( Log.getDebugLevel() > 4 )      
      System.out.println( "--- (FTP) Renamed file [" + url.toString() + 
            "] to [" + url2.toString() + "]" );      
   
   return true;
}

public void lockFileAccess ( String path ) throws IOException
{
   // TODO Auto-generated method stub
   
}

public void unlockFileAccess ( String path ) throws IOException
{
   // TODO Auto-generated method stub
   
}



public String[] list ( String trunk, String trail, boolean recurse ) throws IOException
{
   OurFtpClient ftp;
   TelnetInputStream in;
   ByteArrayOutputStream out;
   URL url;
   ArrayList list;
   String domain, path, base, login, hstr, sarr[];
   int i;
   
   // cannot perform recurse into subdirs
   if ( recurse )
      return null;

   // assemble
   url = new URL( trunk );
   domain = url.getHost();
   path = url.getPath();
   base = trunk.substring( 0, trunk.indexOf( domain ) + domain.length() );
   if ( (login = getLoginEntry( domain )) == null )
      return null;
   
   // connect to host
   ftp = new OurFtpClient( domain );
   i = login.indexOf( ':' );
   ftp.login( login.substring( 0, i ), login.substring( i+1 ) );

   // download file name list 
   in = ftp.nameList( path.concat( "*" ) );
   out = new ByteArrayOutputStream();
   Util.transferData( in, out, 2048 );
   in.close();
   hstr = out.toString( "utf-8" );
   sarr = hstr.split( "\n" );

   // filter list for parameter ending
   list = new ArrayList();
   for ( i = 0; i < sarr.length; i++ )
   {
      hstr = sarr[ i ];
      if ( trail == null || hstr.endsWith( trail ) )
         list.add( base.concat( hstr ) );
   }

   sarr = (String[])list.toArray( new String[ list.size() ] );
   return sarr;
}


public String separator ()
{
   return "/";
}

/* (non-Javadoc)
 * @see org.jpws.pwslib.global.ApplicationAdapter#canWrite()
 */
public boolean canWrite ( String path )
{
   return true;
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
   return true;
}

public long getFileLength ( String path )
{
   return -1;
}

public long getModifiedTime ( String path ) throws IOException
{
   OurFtpClient ftp;
   String domain, login;
   URL url;
   long time = 0;
   int i;
   
   
   url = new URL( path );
   domain = url.getHost();
   if ( (login = getLoginEntry( domain )) == null )
      return 0;

   // create FTP-client and connect to domain  
   ftp = new OurFtpClient( domain );
   i = login.indexOf( ':' );
   ftp.login( login.substring( 0, i ), login.substring( i+1 ) );
   
   // fetch LIST value for path
   try { time = ftp.getFileTime( url.getPath() ); }
   catch ( IOException e )
   { return 0; }
   finally 
   { ftp.closeServer(); }

   return time;
}


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
public boolean equals ( Object obj )
{
   return obj != null && obj instanceof AbstractFTPAdapter;
}

public int hashCode ()
{
   return classID;
}

// *************** INNER CLASSES *********************

public class OurFtpClient extends FtpClient {

   /** New FtpClient connected to host <i>host</i>. */
   public OurFtpClient(String host) throws IOException 
   {
     super(host);
   }

   /** New FullFtpClient connected to host <i>host</i>, port <i>port</i>. */
   public OurFtpClient(String host, int port) throws IOException 
   {
     super(host, port);
   }

   /** Create an uninitialized FullFTP client. */
   public OurFtpClient() 
   {
   }

   /** Delete the file <code>path</code> from the ftp file system */
   public void delete (String path) throws IOException 
   {
     issueCommandCheck("DELE " + path);
   }
   
   public long getFileTime ( String path ) throws IOException
   {
      String ans = "";
      GregorianCalendar cal;
      int y, m, d, h, min, s;  
      
      try {
         issueCommandCheck("MDTM " + path);
         ans = super.getResponseString();
         if ( ans.equals( "" ) | ans.charAt( 0 ) != '2' )
            return 0;
      
         // evaluate answer
         cal = new GregorianCalendar();
         y = Integer.parseInt( ans.substring( 4, 8 ) );
         m = Integer.parseInt( ans.substring( 8, 10 ) ) -1;
         d = Integer.parseInt( ans.substring( 10, 12 ) );
         h = Integer.parseInt( ans.substring( 12, 14 ) );
         min = Integer.parseInt( ans.substring( 14, 16 ) );
         s = Integer.parseInt( ans.substring( 16, 18 ) );
         cal.set( y, m, d, h, min, s );
      }
      catch ( NumberFormatException e )
      {
         return 0;
      }
      catch ( IndexOutOfBoundsException e )
      {
         return 0;
      }
      
      return cal.getTimeInMillis();
   }

   /** Move up one directory in the ftp file system 
   public void cdup() throws IOException 
   {
     issueCommandCheck("CDUP");
   }
*/
   /** Create a new directory named s in the ftp file system 
   public void mkdir(String s) throws IOException 
   {
     issueCommandCheck("MKDIR " + s);
   }
*/
   /** Delete the specified directory from the ftp file system 
   public void rmdir(String s) throws IOException 
   {
     issueCommandCheck("RMD " + s);
   }
*/
   /** Get the name of the present working directory on the ftp file system 
   public String pwd() throws IOException {
     issueCommandCheck("PWD");
     StringBuffer result = new StringBuffer();
     for (Enumeration e = serverResponse.elements(); e.hasMoreElements();) {
       result.append((String) e.nextElement());
     }
     return result.toString();
     
   }
*/
 }

}
