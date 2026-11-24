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

import junit.framework.TestCase;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.log4j.VectorAppender;
import org.apache.log4j.spi.LoggingEvent;
import org.apache.log4j.spi.ThrowableInformation;

import javax.jms.MessageListener;
import javax.jms.Topic;
import javax.jms.TopicConnection;
import javax.jms.TopicConnectionFactory;
import javax.jms.TopicSession;
import javax.jms.TopicSubscriber;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.spi.InitialContextFactory;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Vector;

/**
 * Tests that JMSSink only performs JNDI lookups in the java: namespace, so
 * that a TopicConnectionFactoryBindingName or TopicBindingName handed to it
 * cannot make the sink contact a remote (e.g. LDAP or RMI) server and
 * deserialize whatever that server returns (CVE-2022-23302).
 */
public class JMSSinkTest extends TestCase {

  static final String TCF_BINDING_NAME = "java:comp/env/jms/TopicConnectionFactory";
  static final String TOPIC_BINDING_NAME = "java:comp/env/jms/Topic";

  /** Names handed to the stub JNDI context, in lookup order. */
  static final List LOOKUPS = new ArrayList();

  /** Listeners registered on stub topic subscribers. */
  static final List LISTENERS = new ArrayList();

  private JMSAppenderTest.RogueServer rogueServer;
  private VectorAppender sinkLog;
  private String previousFactory;
  private InputStream previousIn;

  public JMSSinkTest(final String name) {
    super(name);
  }

  protected void setUp() throws IOException {
    LOOKUPS.clear();
    LISTENERS.clear();
    rogueServer = new JMSAppenderTest.RogueServer();
    previousFactory = System.getProperty(Context.INITIAL_CONTEXT_FACTORY);
    System.setProperty(Context.INITIAL_CONTEXT_FACTORY, StubContextFactory.class.getName());
    previousIn = System.in;
    sinkLog = new VectorAppender();
    Logger.getLogger(JMSSink.class).addAppender(sinkLog);
  }

  protected void tearDown() throws InterruptedException {
    LogManager.resetConfiguration();
    System.setIn(previousIn);
    if (previousFactory == null) {
      System.getProperties().remove(Context.INITIAL_CONTEXT_FACTORY);
    } else {
      System.setProperty(Context.INITIAL_CONTEXT_FACTORY, previousFactory);
    }
    rogueServer.shutdown();
  }

  /**
   * TopicConnectionFactoryBindingName pointing at an attacker controlled
   * LDAP server must not result in a JNDI request to that server.
   */
  public void testTopicConnectionFactoryBindingNameOutsideJavaNamespaceIsNotLookedUp() {
    JMSSink sink = new JMSSink(rogueServer.url(), TOPIC_BINDING_NAME, "user", "password");

    assertFalse("JNDI request reached the attacker's server", rogueServer.wasContacted());
    assertEquals("names reached the JNDI context: " + LOOKUPS, 0, LOOKUPS.size());
    assertRestrictionReported(rogueServer.url());
    assertFalse(LISTENERS.contains(sink));
  }

  /**
   * TopicBindingName pointing at an attacker controlled LDAP server must not
   * result in a JNDI request to that server.
   */
  public void testTopicBindingNameOutsideJavaNamespaceIsNotLookedUp() {
    JMSSink sink = new JMSSink(TCF_BINDING_NAME, rogueServer.url(), "user", "password");

    assertFalse("JNDI request reached the attacker's server", rogueServer.wasContacted());
    assertEquals("names reached the JNDI context: " + LOOKUPS, 1, LOOKUPS.size());
    assertEquals(TCF_BINDING_NAME, LOOKUPS.get(0));
    assertRestrictionReported(rogueServer.url());
    assertFalse(LISTENERS.contains(sink));
  }

  /**
   * The same attack delivered through the JMSSink command line.
   */
  public void testMainDoesNotLookUpBindingNamesOutsideJavaNamespace() throws Exception {
    File configFile = File.createTempFile("jmssink", ".properties");
    try {
      FileOutputStream out = new FileOutputStream(configFile);
      out.write("# configuration read by JMSSink.main\n".getBytes());
      out.close();
      System.setIn(new ByteArrayInputStream("exit\n".getBytes()));

      JMSSink.main(new String[] {
          rogueServer.url(), rogueServer.url(), "user", "password", configFile.getAbsolutePath()
      });
    } finally {
      configFile.delete();
    }

    assertFalse("JNDI request reached the attacker's server", rogueServer.wasContacted());
    assertEquals("names reached the JNDI context: " + LOOKUPS, 0, LOOKUPS.size());
    assertRestrictionReported(rogueServer.url());
  }

  /**
   * Names outside the java: namespace are refused before they reach the
   * JNDI context.
   */
  public void testLookupRejectsNamesOutsideJavaNamespace() {
    String[] names = {
        "ldap://127.0.0.1:1389/cn=exploit",
        "ldaps://127.0.0.1:1636/cn=exploit",
        "rmi://127.0.0.1:1099/exploit",
        "iiop://127.0.0.1:900/exploit",
        "dns://127.0.0.1/exploit",
        "corbaname:iiop:127.0.0.1:900#exploit",
        "comp/env/jms/Topic",
        " java:comp/env/jms/Topic"
    };
    Context context = (Context) stub(Context.class);

    for (int i = 0; i < names.length; i++) {
      try {
        JMSSink.lookup(context, names[i]);
        fail("lookup of [" + names[i] + "] was not refused");
      } catch (NamingException e) {
        assertTrue(e.getMessage(), e.getMessage().startsWith(JNDIUtil.RESTRICTION_MSG));
      }
    }
    assertEquals("names reached the JNDI context: " + LOOKUPS, 0, LOOKUPS.size());
  }

  /**
   * Names in the java: namespace are still resolved.
   */
  public void testLookupResolvesJavaNamespace() throws NamingException {
    Context context = (Context) stub(Context.class);

    assertTrue(JMSSink.lookup(context, TCF_BINDING_NAME) instanceof TopicConnectionFactory);
    assertTrue(JMSSink.lookup(context, TOPIC_BINDING_NAME) instanceof Topic);
    assertEquals(2, LOOKUPS.size());
  }

  /**
   * A sink using java: names keeps subscribing to the topic.
   */
  public void testJavaNamespaceBindingNamesAreLookedUp() {
    JMSSink sink = new JMSSink(TCF_BINDING_NAME, TOPIC_BINDING_NAME, "user", "password");

    assertEquals("unexpected errors: " + sinkLog.getVector(), 0, sinkLog.getVector().size());
    assertEquals(2, LOOKUPS.size());
    assertEquals(TCF_BINDING_NAME, LOOKUPS.get(0));
    assertEquals(TOPIC_BINDING_NAME, LOOKUPS.get(1));
    assertEquals(1, LISTENERS.size());
    assertSame(sink, LISTENERS.get(0));
  }

  private void assertRestrictionReported(String name) {
    Vector events = sinkLog.getVector();
    assertEquals("unexpected log events: " + events, 1, events.size());
    ThrowableInformation info = ((LoggingEvent) events.get(0)).getThrowableInformation();
    assertNotNull("no exception logged", info);
    Throwable t = info.getThrowable();
    assertTrue("unexpected error: " + t, t instanceof NamingException);
    assertEquals(JNDIUtil.RESTRICTION_MSG + name, t.getMessage());
  }

  static Object stub(Class type) {
    return Proxy.newProxyInstance(JMSSinkTest.class.getClassLoader(),
        new Class[] { type }, new StubHandler());
  }

  /**
   * JNDI initial context factory handing out the recording stub context.
   */
  public static class StubContextFactory implements InitialContextFactory {
    public Context getInitialContext(Hashtable environment) {
      return (Context) stub(Context.class);
    }
  }

  /**
   * Stand-in for a JNDI context and the JMS objects bound in it. Every name
   * looked up is recorded; only the java: names used by the tests are bound.
   */
  static final class StubHandler implements InvocationHandler {
    public Object invoke(Object proxy, Method method, Object[] args) {
      String methodName = method.getName();
      if ("lookup".equals(methodName)) {
        String name = String.valueOf(args[0]);
        LOOKUPS.add(name);
        if (TCF_BINDING_NAME.equals(name)) {
          return stub(TopicConnectionFactory.class);
        }
        if (TOPIC_BINDING_NAME.equals(name)) {
          return stub(Topic.class);
        }
        return null;
      }
      if ("setMessageListener".equals(methodName)) {
        LISTENERS.add((MessageListener) args[0]);
        return null;
      }
      if ("hashCode".equals(methodName)) {
        return new Integer(System.identityHashCode(proxy));
      }
      if ("equals".equals(methodName)) {
        return proxy == args[0] ? Boolean.TRUE : Boolean.FALSE;
      }
      if ("toString".equals(methodName)) {
        return "stub";
      }
      Class returnType = method.getReturnType();
      if (returnType == TopicConnection.class) {
        return stub(TopicConnection.class);
      }
      if (returnType == TopicSession.class) {
        return stub(TopicSession.class);
      }
      if (returnType == TopicSubscriber.class) {
        return stub(TopicSubscriber.class);
      }
      return null;
    }
  }
}
