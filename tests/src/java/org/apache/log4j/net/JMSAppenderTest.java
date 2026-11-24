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
import org.apache.log4j.Appender;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.apache.log4j.spi.ErrorHandler;
import org.apache.log4j.spi.LoggingEvent;

import javax.jms.Topic;
import javax.jms.TopicConnection;
import javax.jms.TopicConnectionFactory;
import javax.jms.TopicSession;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.spi.InitialContextFactory;
import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Properties;

/**
 * Tests that JMSAppender only performs JNDI lookups in the java: namespace,
 * so that a TopicBindingName or TopicConnectionFactoryBindingName set by
 * whoever can write the log4j configuration cannot make the appender contact
 * a remote (e.g. LDAP or RMI) server (CVE-2021-4104).
 */
public class JMSAppenderTest extends TestCase {

  static final String TCF_BINDING_NAME = "java:comp/env/jms/TopicConnectionFactory";
  static final String TOPIC_BINDING_NAME = "java:comp/env/jms/Topic";

  /** Names handed to the stub JNDI context, in lookup order. */
  static final List LOOKUPS = new ArrayList();

  private RogueServer rogueServer;

  public JMSAppenderTest(final String name) {
    super(name);
  }

  protected void setUp() throws IOException {
    LOOKUPS.clear();
    rogueServer = new RogueServer();
  }

  protected void tearDown() throws InterruptedException {
    LogManager.resetConfiguration();
    rogueServer.shutdown();
  }

  /**
   * TopicConnectionFactoryBindingName pointing at an attacker controlled
   * LDAP server must not result in a JNDI request to that server.
   */
  public void testTopicConnectionFactoryBindingNameOutsideJavaNamespaceIsNotLookedUp() {
    RecordingErrorHandler errorHandler = new RecordingErrorHandler();
    JMSAppender appender = createAppender(rogueServer.url(), TOPIC_BINDING_NAME, errorHandler);

    appender.activateOptions();

    assertFalse("JNDI request reached the attacker's server", rogueServer.wasContacted());
    assertEquals("names reached the JNDI context: " + LOOKUPS, 0, LOOKUPS.size());
    assertRestrictionReported(errorHandler, rogueServer.url());
    assertNull(appender.getTopicConnection());
  }

  /**
   * TopicBindingName pointing at an attacker controlled LDAP server must not
   * result in a JNDI request to that server.
   */
  public void testTopicBindingNameOutsideJavaNamespaceIsNotLookedUp() {
    RecordingErrorHandler errorHandler = new RecordingErrorHandler();
    JMSAppender appender = createAppender(TCF_BINDING_NAME, rogueServer.url(), errorHandler);

    appender.activateOptions();

    assertFalse("JNDI request reached the attacker's server", rogueServer.wasContacted());
    assertEquals("names reached the JNDI context: " + LOOKUPS, 1, LOOKUPS.size());
    assertEquals(TCF_BINDING_NAME, LOOKUPS.get(0));
    assertRestrictionReported(errorHandler, rogueServer.url());
    assertNull(appender.getTopicPublisher());
  }

  /**
   * The same attack delivered through a log4j configuration the attacker
   * can write to.
   */
  public void testConfigurationCannotTriggerLookupOutsideJavaNamespace() {
    Properties props = new Properties();
    props.put("log4j.logger." + JMSAppenderTest.class.getName(), "DEBUG, jms");
    props.put("log4j.appender.jms", JMSAppender.class.getName());
    props.put("log4j.appender.jms.TopicConnectionFactoryBindingName", rogueServer.url());
    props.put("log4j.appender.jms.TopicBindingName", rogueServer.url());

    PropertyConfigurator.configure(props);

    Appender appender = Logger.getLogger(JMSAppenderTest.class).getAppender("jms");
    assertTrue(appender instanceof JMSAppender);
    assertEquals(rogueServer.url(),
        ((JMSAppender) appender).getTopicConnectionFactoryBindingName());
    assertFalse("JNDI request reached the attacker's server", rogueServer.wasContacted());
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
    JMSAppender appender = new JMSAppender();
    Context context = (Context) stub(Context.class);

    for (int i = 0; i < names.length; i++) {
      try {
        appender.lookup(context, names[i]);
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
    JMSAppender appender = new JMSAppender();
    Context context = (Context) stub(Context.class);

    assertTrue(appender.lookup(context, TCF_BINDING_NAME) instanceof TopicConnectionFactory);
    try {
      appender.lookup(context, "java:comp/env/jms/Unbound");
      fail("lookup of an unbound name did not fail");
    } catch (NamingException e) {
      assertEquals("Could not find name [java:comp/env/jms/Unbound].", e.getMessage());
    }
  }

  /**
   * A configuration using java: names keeps working.
   */
  public void testJavaNamespaceBindingNamesAreLookedUp() {
    RecordingErrorHandler errorHandler = new RecordingErrorHandler();
    JMSAppender appender = createAppender(TCF_BINDING_NAME, TOPIC_BINDING_NAME, errorHandler);

    appender.activateOptions();

    assertEquals("unexpected errors: " + errorHandler.errors, 0, errorHandler.errors.size());
    assertEquals(2, LOOKUPS.size());
    assertEquals(TCF_BINDING_NAME, LOOKUPS.get(0));
    assertEquals(TOPIC_BINDING_NAME, LOOKUPS.get(1));
    assertNotNull(appender.getTopicSession());
  }

  private static JMSAppender createAppender(String tcfBindingName, String topicBindingName,
                                            ErrorHandler errorHandler) {
    JMSAppender appender = new JMSAppender();
    appender.setName("jms");
    appender.setErrorHandler(errorHandler);
    appender.setInitialContextFactoryName(StubContextFactory.class.getName());
    appender.setTopicConnectionFactoryBindingName(tcfBindingName);
    appender.setTopicBindingName(topicBindingName);
    return appender;
  }

  private static void assertRestrictionReported(RecordingErrorHandler errorHandler, String name) {
    assertEquals("unexpected errors: " + errorHandler.errors, 1, errorHandler.errors.size());
    Exception e = (Exception) errorHandler.errors.get(0);
    assertTrue("unexpected error: " + e, e instanceof NamingException);
    assertEquals(JNDIUtil.RESTRICTION_MSG + name, e.getMessage());
  }

  static Object stub(Class type) {
    return Proxy.newProxyInstance(JMSAppenderTest.class.getClassLoader(),
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
      return null;
    }
  }

  /**
   * Keeps the errors reported by the appender.
   */
  static final class RecordingErrorHandler implements ErrorHandler {
    final List errors = new ArrayList();

    public void setLogger(Logger logger) {
    }

    public void error(String message, Exception e, int errorCode) {
      errors.add(e);
    }

    public void error(String message) {
      errors.add(new Exception(message));
    }

    public void error(String message, Exception e, int errorCode, LoggingEvent event) {
      errors.add(e);
    }

    public void setAppender(Appender appender) {
    }

    public void setBackupAppender(Appender appender) {
    }

    public void activateOptions() {
    }
  }

  /**
   * Stands in for an attacker controlled LDAP server: records whether
   * anybody connected and drops every connection right away.
   */
  static final class RogueServer implements Runnable {
    private final ServerSocket serverSocket;
    private final Thread thread;
    private volatile boolean contacted;

    RogueServer() throws IOException {
      serverSocket = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
      thread = new Thread(this, "rogue-ldap-server");
      thread.setDaemon(true);
      thread.start();
    }

    String url() {
      return "ldap://127.0.0.1:" + serverSocket.getLocalPort() + "/cn=exploit";
    }

    boolean wasContacted() {
      return contacted;
    }

    public void run() {
      try {
        while (true) {
          Socket socket = serverSocket.accept();
          contacted = true;
          socket.close();
        }
      } catch (IOException e) {
        // the server socket was closed by shutdown()
      }
    }

    void shutdown() throws InterruptedException {
      try {
        serverSocket.close();
      } catch (IOException e) {
        // ignored
      }
      thread.join(5000);
    }
  }
}
