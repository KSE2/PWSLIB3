/*
 *  PwsFileListener in org.jpws.pwslib.data
 *  file: PwsFileListener.java
 * 
 *  Project JPasswords
 *  @author Wolfgang Keller
 *  Created 27.09.2004
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

package org.jpws.pwslib.data;

/**
 *  Interface defines a state change notification method for listeners for
 *  PWS record lists and their modifications. The type of events that may be 
 *  issued are defined by the <code>PwsFileEvent</code> class. 
 *  
 *  @see org.jpws.pwslib.data.PwsRecordList
 */
public interface PwsFileListener
{
   public void fileStateChanged ( PwsFileEvent evt );
}
