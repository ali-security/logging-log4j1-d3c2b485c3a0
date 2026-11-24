/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.log4j.chainsaw;

import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Set;

import junit.framework.TestCase;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.spi.LoggingEvent;

/**
 * Tests that the Chainsaw {@link LoggingReceiver} rejects the CVE-2023-26464
 * payload: a logging event carrying deeply nested hash-based collections
 * whose hashCode() computation during deserialization never terminates.
 */
public class LoggingReceiverTest extends TestCase {

    /**
     * How long the client waits for the receiver to drop the connection.
     */
    private static final int TIMEOUT_MILLIS = 20000;

    public LoggingReceiverTest(final String name) {
        super(name);
    }

    private static Set createNestedHashSets(int depth) {
        Set root = new HashSet();
        Set s1 = root;
        Set s2 = new HashSet();
        for (int i = 0; i < depth; i++) {
            Set t1 = new HashSet();
            Set t2 = new HashSet();
            t1.add("foo");
            s1.add(t1);
            s1.add(t2);
            s2.add(t1);
            s2.add(t2);
            s1 = t1;
            s2 = t2;
        }
        return root;
    }

    public void testNestedCollectionsCloseConnection() throws Exception {
        ServerSocket probe = new ServerSocket(0);
        int port = probe.getLocalPort();
        probe.close();

        LoggingReceiver receiver = new LoggingReceiver(new MyTableModel(), port);
        receiver.start();

        Hashtable properties = new Hashtable();
        properties.put("attack", createNestedHashSets(100));
        LoggingEvent event = new LoggingEvent(Logger.class.getName(),
                Logger.getLogger(LoggingReceiverTest.class), System.currentTimeMillis(), Level.INFO, "attack",
                "main", null, null, null, properties);

        Socket client = new Socket("localhost", port);
        try {
            client.setSoTimeout(TIMEOUT_MILLIS);
            ObjectOutputStream oos = new ObjectOutputStream(client.getOutputStream());
            oos.writeObject(event);
            oos.flush();
            try {
                assertEquals("receiver should close the connection", -1, client.getInputStream().read());
            } catch (SocketTimeoutException e) {
                fail("LoggingReceiver did not reject the nested collections within " + TIMEOUT_MILLIS + " ms");
            } catch (SocketException e) {
                // connection reset by the receiver: it gave up on the payload
            }
        } finally {
            client.close();
        }
    }
}
