/*
 *  Log in org.jpws.pwslib.global
 *  file: Log.java
 * 
 *  Project JPasswords
 *  @author Wolfgang Keller
 *  Created 23.08.2004
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

package org.jpws.pwslib.global;

import java.io.PrintStream;
import java.util.ArrayList;

import javax.swing.SwingUtilities;

/**
 *  Log in org.jpws.pwslib.global
 *  <p>Protocol, log and debug printing class.
 */
public class Log
{
   public static final int DEFAULT_DEBUGLEVEL = 1;
   public static final int DEFAULT_LOGLEVEL = 1;
   
   public static PrintStream out = System.out;
   public static PrintStream err = System.err;
   
   
   private static String logName = "jpws-b";
   private static int debugLevel = DEFAULT_DEBUGLEVEL;
   private static int logLevel = DEFAULT_LOGLEVEL;
   private static boolean debug = true;
   private static boolean logging = true;
   
   private static ArrayList<String> excludeList = new ArrayList<String>(); 

   static {
      excludeList.add( "(PwsRecord." );
      excludeList.add( "(PwsRecord)" );
      excludeList.add( "(CryptoRandom" );
      excludeList.add( "(PwsFileFactory" );
      excludeList.add( "(PwsRecList" );
//      excludeList.add( "(MenuHandler" );
      excludeList.add( "(DisplayManager" );
      excludeList.add( "(ButtonBarDialog" );
      excludeList.add( "(DialogButtonBar" );
      excludeList.add( "(PwsFile." );
      excludeList.add( "(PwsFile)" );
   }
/**
 * 
 */
private Log () {
}

private static String getThreadName () {
   String thdName = SwingUtilities.isEventDispatchThread() ? "[EDT] " : "[THD] "; 
   return thdName;
}

public static void debug ( int level, Object obj ) {
   if ( debug && level <= debugLevel && !excluded(obj.toString() ) )
      out.println( logName + " DEB " + getThreadName() + String.valueOf(obj) );
}

public static void debug ( int level, String str ) {
   debug( level, (Object)str );
}

public static void setDebug ( boolean v ) {
   debug = v;
}

public static void setDebugLevel ( int v ) {
   debugLevel = v;
}

public static void setModuleName ( String name ) {
   logName = name;
}

public static void log ( int level, String str ) {
   if ( logging && level <= logLevel && !excluded(str) )
      out.println( logName + " log " + getThreadName() + str );
}

public static void setLogging ( boolean v ) {
   logging = v;
}

public static void setLogLevel ( int v ) {
   logLevel = v;
}

/** The current logging report level.
 *  @since 0-3-0
 */
public static int getLogLevel () {
   return logLevel;
}

/** The current debugging report level.
 *  @since 0-3-0
 */
public static int getDebugLevel () {
   return debugLevel;
}

public static void error ( int level, Object obj ) {
   if ( debug && level <= debugLevel )
      err.println( logName + " ERR: " + getThreadName() + " *** " + String.valueOf(obj) );
}

public static void error ( int level, String str ) {
   error( level, (Object)str );
}


private static boolean excluded ( String msg ) {
   for ( String token : excludeList ) {
      if ( msg.indexOf(token) > -1 )
         return true;
   }
   return false;
}

}
