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
package dibd.storage.impl;

import java.sql.SQLException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import dibd.storage.StorageBackendException;
import dibd.storage.StorageNNTP;
import dibd.storage.StorageProvider;

/**
 * 
 * @author Christian Lins
 * @since sonews/1.0
 */
public class JDBCStorageProvider implements StorageProvider {

    protected static final Map<Thread, JDBCDatabase> instances = new ConcurrentHashMap<>();

    @Override
    public boolean isSupported(String uri) {
        return uri.startsWith("jdbc:mysql")
                || uri.startsWith("jdbc:postgresql");
    }

    @Override
    public StorageNNTP storage(Thread thread) throws StorageBackendException {
    	//System.out.println(thread);
        try {
            if (!instances.containsKey(Thread.currentThread())) {
                JDBCDatabase db = new JDBCDatabase();
                db.arise();
                instances.put(Thread.currentThread(), db);
                return db;
            } else {
                return instances.get(Thread.currentThread());
            }
        } catch (SQLException ex) {
            throw new StorageBackendException(ex);
        }
    }
}