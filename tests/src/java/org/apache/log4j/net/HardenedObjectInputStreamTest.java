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
package org.apache.log4j.net;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.AbstractMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

import junit.framework.TestCase;

import org.apache.log4j.AppenderSkeleton;
import org.apache.log4j.Hierarchy;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.spi.LoggingEvent;
import org.apache.log4j.spi.RootLogger;

/**
 * Tests for {@link HardenedObjectInputStream} collection count limiting
 * that mitigates CVE-2023-26464.
 *
 * CVE-2023-26464: Deeply nested hash-based collection structures cause
 * exponential hashCode() computation during deserialization, leading
 * to Denial of Service. The fix limits the total number of Map/Collection
 * instances that can be deserialized in a single object graph.
 */
public class HardenedObjectInputStreamTest extends TestCase {

    private byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(obj);
        oos.close();
        return bos.toByteArray();
    }

    /**
     * CVE-2023-26464: The exact attack payload from the logback advisory.
     * Deeply nested HashSet structures that cause exponential hashCode()
     * computation. The collection count limit must reject this before
     * the computation becomes dangerous.
     */
    public void testDeeplyNestedHashSetRejected() throws Exception {
        // Build the CVE-2023-26464 attack payload: deeply nested HashSets
        // that form a DAG causing O(2^N) hashCode() computation
        Set root = new HashSet();
        Set s1 = root;
        Set s2 = new HashSet();
        for (int i = 0; i < 100; i++) {
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
        byte[] serialized = serialize(root);

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        try {
            hois.readObject();
            fail("Deeply nested HashSet should be rejected due to collection count limit");
        } catch (InvalidObjectException e) {
            // Our resolveObject-based collection count limit caught it (pre-JDK 9)
            assertTrue("Should mention collection limit",
                    e.getMessage().contains("collection"));
        } catch (java.io.InvalidClassException e) {
            // On JDK 9+, the built-in ObjectInputFilter may reject it first
            // with "filter status: REJECTED". Either way, the attack is blocked.
        } finally {
            hois.close();
        }
    }

    /**
     * A moderate number of nested collections (within the limit) should
     * still be allowed. This tests that normal LoggingEvent-like payloads
     * with a few Hashtables work fine.
     */
    public void testModerateCollectionsAllowed() throws Exception {
        // Simulate a LoggingEvent with MDC (Hashtable) containing a few entries
        Hashtable mdc = new Hashtable();
        mdc.put("user", "alice");
        mdc.put("session", "abc123");
        mdc.put("requestId", "req-456");
        byte[] serialized = serialize(mdc);

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        Object result = hois.readObject();
        assertTrue(result instanceof Hashtable);
        assertEquals("alice", ((Hashtable) result).get("user"));
        hois.close();
    }

    /**
     * Simple non-collection objects should work unaffected.
     */
    public void testStringAllowed() throws Exception {
        byte[] serialized = serialize("hello world");

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        assertEquals("hello world", hois.readObject());
        hois.close();
    }

    /**
     * Upper bound for a single deserialization in the tests below. Without
     * the collection count limit the attack payloads never terminate.
     */
    private static final long TIMEOUT_MILLIS = 20000;

    /**
     * Number of legitimate events sent over one stream; larger than
     * MAX_COLLECTION_COUNT so that the budget must be reset per event.
     */
    private static final int LEGITIMATE_EVENT_COUNT = HardenedObjectInputStream.MAX_COLLECTION_COUNT + 8;

    /**
     * Builds the CVE-2023-26464 payload: a DAG of nested HashSets whose
     * hashCode() costs O(2^depth).
     */
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

    private static LoggingEvent createEvent(String message, Map properties) {
        Logger logger = Logger.getLogger(HardenedObjectInputStreamTest.class);
        return new LoggingEvent(Logger.class.getName(), logger, System.currentTimeMillis(), Level.INFO, message,
                "main", null, null, null, properties);
    }

    private static Map createMdc(int i) {
        Map mdc = new HashMap();
        mdc.put("requestId", "req-" + i);
        return mdc;
    }

    /**
     * Reads one object on a separate daemon thread, so that unbounded
     * hashCode() computation fails the test instead of hanging the build.
     *
     * @return the exception thrown by the read, or null if it succeeded
     */
    private Throwable readAdaptedObjectWithTimeout(final HardenedObjectInputStream hois) throws InterruptedException {
        final Throwable[] thrown = new Throwable[1];
        Thread reader = new Thread(new Runnable() {
            public void run() {
                try {
                    hois.readAdaptedObject();
                } catch (Throwable t) {
                    thrown[0] = t;
                }
            }
        }, "HardenedObjectInputStreamTest-reader");
        reader.setDaemon(true);
        reader.start();
        reader.join(TIMEOUT_MILLIS);
        assertFalse("Deserialization did not complete within " + TIMEOUT_MILLIS + " ms", reader.isAlive());
        return thrown[0];
    }

    private void assertRejected(Throwable thrown) {
        assertTrue("Expected InvalidObjectException but got " + thrown, thrown instanceof InvalidObjectException);
    }

    /**
     * CVE-2023-26464 names deeply nested hashmaps: a DAG of nested HashMaps
     * used as keys must be rejected like the HashSet payload.
     */
    public void testDeeplyNestedHashMapRejected() throws Exception {
        Map root = new HashMap();
        Map m1 = root;
        Map m2 = new HashMap();
        for (int i = 0; i < 100; i++) {
            Map t1 = new HashMap();
            Map t2 = new HashMap();
            t1.put("foo", "bar");
            m1.put(t1, t2);
            m2.put(t1, t2);
            m1 = t1;
            m2 = t2;
        }
        HardenedObjectInputStream hois = new HardenedObjectInputStream(
                new ByteArrayInputStream(serialize(root)), new String[0]);
        try {
            assertRejected(readAdaptedObjectWithTimeout(hois));
        } finally {
            hois.close();
        }
    }

    /**
     * The attack as received by SocketNode and Chainsaw: a logging event whose
     * MDC Hashtable carries the nested collections.
     */
    public void testNestedCollectionsInLoggingEventRejected() throws Exception {
        Map properties = new HashMap();
        properties.put("attack", createNestedHashSets(100));
        byte[] serialized = serialize(createEvent("attack", properties));

        HardenedLoggingEventInputStream hleis = new HardenedLoggingEventInputStream(
                new ByteArrayInputStream(serialized));
        try {
            assertRejected(readAdaptedObjectWithTimeout(hleis));
        } finally {
            hleis.close();
        }
    }

    /**
     * Map.Entry implementations from java.util (whitelisted) also hash their
     * key and value recursively; nesting them inside a single set must not
     * bypass the limit.
     */
    public void testNestedMapEntriesRejected() throws Exception {
        Object nested = "foo";
        for (int i = 0; i < 100; i++) {
            nested = new AbstractMap.SimpleEntry(nested, nested);
        }
        // add the holder while it is cheap to hash, then attach the chain
        AbstractMap.SimpleEntry holder = new AbstractMap.SimpleEntry("attack", null);
        Set root = new HashSet();
        root.add(holder);
        holder.setValue(nested);

        HardenedObjectInputStream hois = new HardenedObjectInputStream(
                new ByteArrayInputStream(serialize(root)), new String[0]);
        try {
            assertRejected(readAdaptedObjectWithTimeout(hois));
        } finally {
            hois.close();
        }
    }

    /**
     * Each event read with readAdaptedObject gets its own collection budget,
     * so a long-lived connection is not cut off after MAX_COLLECTION_COUNT
     * events carrying an MDC.
     */
    public void testCollectionBudgetIsPerEvent() throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        for (int i = 0; i < LEGITIMATE_EVENT_COUNT; i++) {
            oos.writeObject(createEvent("event " + i, createMdc(i)));
        }
        oos.close();

        HardenedLoggingEventInputStream hleis = new HardenedLoggingEventInputStream(
                new ByteArrayInputStream(bos.toByteArray()));
        try {
            for (int i = 0; i < LEGITIMATE_EVENT_COUNT; i++) {
                LoggingEvent event = (LoggingEvent) hleis.readAdaptedObject();
                assertEquals("event " + i, event.getRenderedMessage());
                assertEquals("req-" + i, event.getMDC("requestId"));
            }
        } finally {
            hleis.close();
        }
    }

    /**
     * End-to-end over a socket: SocketNode must keep delivering legitimate
     * events, then drop the connection promptly when it receives the
     * CVE-2023-26464 payload instead of spinning on hashCode().
     */
    public void testSocketNodeRejectsNestedCollections() throws Exception {
        Hierarchy hierarchy = new Hierarchy(new RootLogger(Level.DEBUG));
        CollectingAppender appender = new CollectingAppender();
        hierarchy.getRootLogger().addAppender(appender);

        Map properties = new HashMap();
        properties.put("attack", createNestedHashSets(100));
        LoggingEvent attack = createEvent("attack", properties);

        ServerSocket serverSocket = new ServerSocket(0);
        Socket client = null;
        try {
            client = new Socket("localhost", serverSocket.getLocalPort());
            Socket accepted = serverSocket.accept();
            ObjectOutputStream oos = new ObjectOutputStream(client.getOutputStream());
            oos.flush();

            Thread node = new Thread(new SocketNode(accepted, hierarchy), "HardenedObjectInputStreamTest-node");
            node.setDaemon(true);
            node.start();

            for (int i = 0; i < LEGITIMATE_EVENT_COUNT; i++) {
                oos.writeObject(createEvent("event " + i, createMdc(i)));
            }
            oos.writeObject(attack);
            oos.flush();

            node.join(TIMEOUT_MILLIS);
            assertFalse("SocketNode did not reject the nested collections within " + TIMEOUT_MILLIS + " ms",
                    node.isAlive());
            assertEquals(LEGITIMATE_EVENT_COUNT, appender.messages.size());
            assertFalse(appender.messages.contains("attack"));
        } finally {
            if (client != null) {
                client.close();
            }
            serverSocket.close();
        }
    }

    /**
     * Records the messages of the events delivered by SocketNode.
     */
    static final class CollectingAppender extends AppenderSkeleton {
        final Vector messages = new Vector();

        protected void append(LoggingEvent event) {
            messages.addElement(event.getRenderedMessage());
        }

        public boolean requiresLayout() {
            return false;
        }

        public void close() {
            this.closed = true;
        }
    }
}
