/*
 *  File: StreamFactory.java
 * 
 *  Project PWSLIB3
 *  @author Wolfgang Keller
 *  Created 04.08.2004
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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.jpws.pwslib.exception.ApplicationFailureException;
import org.jpws.pwslib.global.Global;

import kse.utilclass.misc.Log;


/**
 * <code>StreamFactory</code> obtains input and output streams from
 * an application specific IO-context (<code>ApplicationAdapter</code>)
 * and reproduces them in wrapping classes for the purposes of the backend 
 * library. It will not cause a functional error to address application
 * streams directly at the adapter, but for systematic reasons and tracing and 
 * performance benefits, it is preferable to use <code>StreamFactory</code>
 * instead.  
 */
public class StreamFactory
{
   
   // Singleton pattern
   private StreamFactory ()
   {}
   
   /**
    * Returns an input stream for a file that was obtained from the standard 
    * application IO-context (by default the local file system).
    *  
    * @param path the file path for the file to be read
    * @return a buffered input stream for the file specified  
    * 
    * @throws IOException
    * @throws ApplicationFailureException if the IO-context fails to render
    *         an input stream
    * @throws IllegalArgumentException if the parameter is void or empty 
    */
   public static InputStream getInputStream ( String   path ) 
         throws IOException, ApplicationFailureException
   {
      return getInputStream( Global.getStandardApplication(), path );
   }
   
   /**
    * Returns an output stream for a file that was obtained from the standard 
    * application IO-context (by default the local file system).
    *  
    * @param path the file path for the file to be written
    * @return a buffered output stream for the file specified  
    * 
    * @throws IOException
    * @throws ApplicationFailureException if the IO-context fails to render
    *         an output stream
    * @throws IllegalArgumentException if the parameter is void or empty 
    */
   public static OutputStream getOutputStream ( String   path ) 
         throws IOException, ApplicationFailureException
   {
      return getOutputStream( Global.getStandardApplication(), path );
   }

   /**
    * Returns an input stream for a file that was obtained from the specified 
    * application context.
    *  
    * @param application the addressed IO-context
    * @param path the file path, valid for the application adapter
    * @return a buffered input stream for the file specified  
    * 
    * @throws IOException
    * @throws ApplicationFailureException if the IO-context fails to render
    *         an input stream
    * @throws NullPointerException if any parameter is void 
    * @throws IllegalArgumentException if path is empty 
    */
   public static InputStream getInputStream (
               ApplicationAdapter application,
               String   path
               ) throws IOException, ApplicationFailureException
   {
      InputStream in;
      
      if ( application == null | path == null )
         throw new NullPointerException(); 
      if ( path.equals("") )
         throw new IllegalArgumentException();
      
      if ( (in = application.getInputStream( path )) == null )
         throw new ApplicationFailureException("void input stream [" + path 
               + "] <- " + application.getName() );
      
      return new SFInputStream( in, application, path );
   } // getInputStream 


   /**
    * Returns an output stream for a file that was obtained from the specified 
    * application context.
    *  
    * @param application the addressed IO-context
    * @param path the file path, valid for the application adapter
    * @return a buffered output stream for the file specified  
    * 
    * @throws IOException
    * @throws ApplicationFailureException if the IO-context fails to render
    *         an output stream
    * @throws IllegalArgumentException if any parameter is void or empty 
    */
   public static OutputStream getOutputStream (
         ApplicationAdapter application,
         String   path
         ) throws IOException, ApplicationFailureException
   {
      OutputStream out;
      String hstr;
      
      if ( application == null || path == null || path.isEmpty() )
          throw new IllegalArgumentException();
      
      if ( !application.canWrite( path ) ) {
         hstr = "adapter not qualified for output: [" + path + "] <- " + application.getName();
         throw new ApplicationFailureException( hstr );
      }
      
      if ( (out = application.getOutputStream( path )) == null ) {
         hstr = "void output stream [" + path + "] <- " + application.getName();
         throw new ApplicationFailureException( hstr );
      }
         
      return new SFOutputStream( out, application, path );
   }  // getOutputStream  

   //  *********  INNER CLASSES  *************
   
private static class SFInputStream extends BufferedInputStream
{
   private String filepath;
   private ApplicationAdapter application;
   
   public SFInputStream ( InputStream in, 
                          ApplicationAdapter app, 
                          String path )
   {
      super( in );
      filepath = path;
      application = app;

      Log.log( 9, "(StreamFactory) opened InputStream for \"" 
            + application.getName() + "\" -> " + path );
   }  // constructor
   
   
   @Override
   public void close () throws IOException
   {
      super.close();
      Log.log( 9, "(StreamFactory) closed InputStream for \""  
            + application.getName() + "\" -> " + filepath );
   }

   /**
    * This read modification performs multiple read attempts until
    * the requested data length or -1 if received.
    * (This was necessitated by a possible (mis-)behaviour of IP
    * transfer handling causing a transmission error.)
    *  
    */
   @Override
   public synchronized int read ( byte[] b, int off, int len ) throws IOException
   {
      int rlen, r;
      
      r = rlen = super.read( b, off, len );
      while ( r > -1 && rlen < len ) {
         // second attempt
         r = super.read( b, off+rlen, len-rlen );
         if ( r > 0 ) {
            rlen += r;
         }
      }
      return rlen; 
   }
}  // inner class FFInputStream

private static class SFOutputStream extends BufferedOutputStream
{
   private String filepath;
   private ApplicationAdapter application;
   private boolean isClosed;
   
   public SFOutputStream ( OutputStream out, 
                          ApplicationAdapter app, 
                          String path )
   {
      super( out );
      filepath = path;
      application = app;

      Log.log( 9, "(StreamFactory) opened OutputStream for \"" 
            + application.getName() + "\" -> " + path );
   }  // constructor
   
   
   @Override
public void close () throws IOException
   {
      if ( isClosed ) return;
      
      try { 
    	  super.flush(); 
      } finally {
         super.close();
         isClosed = true;
         
         Log.log( 9, "(StreamFactory) closed OutputStream for \""  
               + application.getName() + "\" -> " + filepath );
      }
   }
}  // inner class FFOutputStream

}

