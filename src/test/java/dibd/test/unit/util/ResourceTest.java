/*
 *   SONEWS News Server
 *   see AUTHORS for the list of contributors
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package dibd.test.unit.util;

import junit.framework.TestCase;
import dibd.util.io.Resource;

/**
 * Unit test for class dibd.util.io.Resource.
 * @author Christian Lins
 * @see dibd.util.io.Resource
 * @since sonews/0.5.0
 */
public class ResourceTest extends TestCase
{

  public void testGetAsURL()
  {
    Object url;
    
    url = Resource.getAsURL(null);
    assertNull(url);
    
    url = Resource.getAsURL("this is absolutely bullshit");
    assertNull(url);
    
    // This file should exist
    url = Resource.getAsURL("dibd/App.class");
    assertNotNull(url);
  }
  
  public void testGetAsStream()
  {
    Object stream;
    
    stream = Resource.getAsStream(null);
    assertNull(stream);
    
    stream = Resource.getAsStream("this is bullshit");
    assertNull(stream);
    
    stream = Resource.getAsStream("dibd/App.class");
    assertNotNull(stream);
  }
  
  public void testGetAsString()
  {
    String str;
    
    str = Resource.getAsString(null, true);
    assertNull(str);
    
    str = Resource.getAsString("this is bullshit", true);
    assertNull(str);
    
    str = Resource.getAsString("dibd/App.class", true);
    assertNotNull(str);
    
    str = Resource.getAsString("dibd/App.class", false);
    assertNotNull(str);
    assertEquals(str.indexOf("\n"), -1);
  }
  
}
