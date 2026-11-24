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
package org.apache.log4j.jdbc;

import junit.framework.TestCase;

import org.apache.log4j.EnhancedPatternLayout;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.apache.log4j.NDC;
import org.apache.log4j.PropertyConfigurator;
import org.apache.log4j.VectorErrorHandler;
import org.apache.log4j.spi.ErrorCode;
import org.apache.log4j.xml.XLevel;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Tests for JDBCAppender, including the SQL injection of CVE-2022-23305.
 */
public class JdbcAppenderTest extends TestCase {
    private static final String DB_URL = "jdbc:h2:mem:test_db";

    // Closing the last connection to "in-memory h2" removes the database
    // So we keep the connection during the test
    // The logger opens its own connection
    Connection con;

    Logger logger = Logger.getLogger(JdbcAppenderTest.class);

    public JdbcAppenderTest(final String name) {
	super(name);
    }

    public void setUp() throws SQLException {
	try {
	    // Explicitly load the H2 driver
	    Class.forName("org.h2.Driver");
	} catch (ClassNotFoundException e) {
	    throw new RuntimeException("H2 Driver not found in classpath: " + e);
	}

	con = DriverManager.getConnection(DB_URL);
	Statement st = con.createStatement();
	try {
	    st.execute(
		    "create table logs(level varchar(100),location varchar(100),message varchar(100),message2 varchar(100))");
	} finally {
	    st.close();
	}
    }

    public void tearDown() throws SQLException {
	LogManager.shutdown();
	con.close();
    }

    public void testVerifyJdbcBufferSize1() throws SQLException {
	PropertyConfigurator.configure("input/jdbc_h2_bufferSize1.properties");

	String oldThreadName = Thread.currentThread().getName();
	try {
	    Thread.currentThread().setName("main");
	    logger.debug("message with ' quote");
	    assertEquals("batchSize=1, so messages should be added immediately",
		    "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n",
		    joinSorted(getMessagesFromDababase()));

	    logger.fatal("message with \" quote");

	    assertEquals("batchSize=1, so two messages should be in DB after two logging calls",
		    "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n"
			    + "FATAL; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest FATAL message with \" quote\n",
		    joinSorted(getMessagesFromDababase()));
	} finally {
	    Thread.currentThread().setName(oldThreadName);
	}
    }

    public void testVerifyJdbcBufferSize2() throws SQLException {
	PropertyConfigurator.configure("input/jdbc_h2_bufferSize2.properties");

	String oldThreadName = Thread.currentThread().getName();
	try {
	    Thread.currentThread().setName("main");
	    logger.log(XLevel.TRACE, "xtrace message");
	    logger.debug("message with ' quote");
	    logger.info("message with \" quote");
	    logger.warn("?");
	    // bufferSize=2, so this messsage won't yet be stored to the db
	    logger.error("m4");

	    assertEquals(
		    "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n"
			    + "INFO; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest INFO message with \" quote\n"
			    + "TRACE; org.apache.log4j.jdbc.JdbcAppenderTest; xtrace message;  org.apache.log4j.jdbc.JdbcAppenderTest TRACE xtrace message\n"
			    + "WARN; org.apache.log4j.jdbc.JdbcAppenderTest; ?;  org.apache.log4j.jdbc.JdbcAppenderTest WARN ?\n",
		    joinSorted(getMessagesFromDababase()));

	    logger.fatal("m5");

	    assertEquals("Logging m5 message should trigger buffer flush for both m4 and m5",
		    "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n"
			    + "ERROR; org.apache.log4j.jdbc.JdbcAppenderTest; m4;  org.apache.log4j.jdbc.JdbcAppenderTest ERROR m4\n"
			    + "FATAL; org.apache.log4j.jdbc.JdbcAppenderTest; m5;  org.apache.log4j.jdbc.JdbcAppenderTest FATAL m5\n"
			    + "INFO; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest INFO message with \" quote\n"
			    + "TRACE; org.apache.log4j.jdbc.JdbcAppenderTest; xtrace message;  org.apache.log4j.jdbc.JdbcAppenderTest TRACE xtrace message\n"
			    + "WARN; org.apache.log4j.jdbc.JdbcAppenderTest; ?;  org.apache.log4j.jdbc.JdbcAppenderTest WARN ?\n",
		    joinSorted(getMessagesFromDababase()));
	} finally {
	    Thread.currentThread().setName(oldThreadName);
	}
    }

    /**
     * CVE-2022-23305: a logged message must not be able to close the SQL
     * string literal and append its own SQL statements.
     */
    public void testSqlInjectionThroughMessageIsNotExecuted() throws SQLException {
	PropertyConfigurator.configure("input/jdbc_h2_bufferSize1.properties");
	VectorErrorHandler errorHandler = new VectorErrorHandler();
	LogManager.getRootLogger().getAppender("A").setErrorHandler(errorHandler);

	String payload = "x', 'y'); create table pwned_message(a int); --";
	String oldThreadName = Thread.currentThread().getName();
	try {
	    Thread.currentThread().setName("main");
	    logger.info(payload);
	} finally {
	    Thread.currentThread().setName(oldThreadName);
	}

	assertFalse("the logged message was executed as SQL", tableExists("PWNED_MESSAGE"));
	assertEquals("the logged message must be stored as is, " + errors(errorHandler),
		"INFO; org.apache.log4j.jdbc.JdbcAppenderTest; " + payload
			+ ";  org.apache.log4j.jdbc.JdbcAppenderTest INFO " + payload + "\n",
		joinSorted(getMessagesFromDababase()));
	assertEquals("no error expected, " + errors(errorHandler), 0, errorHandler.size());
    }

    /**
     * CVE-2022-23305: MDC values, the NDC and the thread name are as
     * attacker controlled as the message and must not be executed as SQL
     * either. The appender is configured programmatically, without calling
     * activateOptions().
     */
    public void testSqlInjectionThroughMdcNdcAndThreadNameIsNotExecuted() throws SQLException {
	JDBCAppender appender = newH2Appender();
	VectorErrorHandler errorHandler = new VectorErrorHandler();
	appender.setErrorHandler(errorHandler);
	appender.setSql("insert into logs(level,location,message,message2) values('%p','%X{user}','%x','%t')");
	Logger jdbcLogger = Logger.getLogger("org.apache.log4j.jdbc.programmatic");
	jdbcLogger.setAdditivity(false);
	jdbcLogger.addAppender(appender);

	String mdcPayload = "u', '', ''); create table pwned_mdc(a int); --";
	String ndcPayload = "n', ''); create table pwned_ndc(a int); --";
	String threadPayload = "t'); create table pwned_thread(a int); --";
	String oldThreadName = Thread.currentThread().getName();
	try {
	    Thread.currentThread().setName("main");
	    MDC.put("user", mdcPayload);
	    jdbcLogger.info("mdc");
	    MDC.remove("user");

	    NDC.push(ndcPayload);
	    jdbcLogger.info("ndc");
	    NDC.remove();

	    Thread.currentThread().setName(threadPayload);
	    jdbcLogger.info("thread");
	} finally {
	    Thread.currentThread().setName(oldThreadName);
	    MDC.remove("user");
	    NDC.remove();
	    jdbcLogger.removeAppender(appender);
	    appender.close();
	}

	assertFalse("the MDC value was executed as SQL", tableExists("PWNED_MDC"));
	assertFalse("the NDC was executed as SQL", tableExists("PWNED_NDC"));
	assertFalse("the thread name was executed as SQL", tableExists("PWNED_THREAD"));

	List expected = new ArrayList();
	expected.add("INFO; " + mdcPayload + "; ; main");
	expected.add("INFO; ; " + ndcPayload + "; main");
	expected.add("INFO; ; ; " + threadPayload);
	assertEquals("event values must be stored as is, " + errors(errorHandler),
		joinSorted(expected), joinSorted(getMessagesFromDababase()));
	assertEquals("no error expected, " + errors(errorHandler), 0, errorHandler.size());
    }

    /**
     * CVE-2022-23305: only PatternLayout can be turned into a parameterized
     * statement, any other layout would format event values straight into
     * the SQL, so it must be rejected and nothing executed.
     */
    public void testLayoutOtherThanPatternLayoutIsRejected() throws SQLException {
	JDBCAppender appender = newH2Appender();
	VectorErrorHandler errorHandler = new VectorErrorHandler();
	appender.setErrorHandler(errorHandler);
	appender.setLayout(new EnhancedPatternLayout(
		"insert into logs(level,location,message,message2) values('%p','%c','%m','x')"));
	Logger jdbcLogger = Logger.getLogger("org.apache.log4j.jdbc.enhanced");
	jdbcLogger.setAdditivity(false);
	jdbcLogger.addAppender(appender);

	try {
	    jdbcLogger.info("x', 'y'); create table pwned_layout(a int); --");
	} finally {
	    jdbcLogger.removeAppender(appender);
	    appender.close();
	}

	assertFalse("the logged message was executed as SQL", tableExists("PWNED_LAYOUT"));
	assertEquals("nothing must be inserted", "", joinSorted(getMessagesFromDababase()));
	assertEquals("the layout must be rejected, " + errors(errorHandler), 1, errorHandler.size());
	assertEquals(ErrorCode.MISSING_LAYOUT, errorHandler.getErrorCode(0));
    }

    private static JDBCAppender newH2Appender() {
	JDBCAppender appender = new JDBCAppender();
	appender.setDriver("org.h2.Driver");
	appender.setURL(DB_URL);
	appender.setUser("");
	appender.setPassword("");
	return appender;
    }

    private static String errors(VectorErrorHandler errorHandler) {
	StringBuffer sb = new StringBuffer("errors: [");
	for (int i = 0; i < errorHandler.size(); i++) {
	    sb.append(errorHandler.getMessage(i)).append(": ").append(errorHandler.getException(i)).append("; ");
	}
	return sb.append(']').toString();
    }

    private static String joinSorted(List list) {
	Collections.sort(list);
	StringBuffer sb = new StringBuffer();
	for (int i = 0; i < list.size(); i++) {
	    String s = (String) list.get(i);
	    sb.append(s).append('\n');
	}
	return sb.toString();
    }

    private boolean tableExists(String tableName) throws SQLException {
	PreparedStatement ps = con.prepareStatement(
		"select count(*) from information_schema.tables where table_name = ?");
	try {
	    ps.setString(1, tableName);
	    ResultSet rs = ps.executeQuery();
	    try {
		rs.next();
		return rs.getInt(1) > 0;
	    } finally {
		rs.close();
	    }
	} finally {
	    ps.close();
	}
    }

    private List getMessagesFromDababase() throws SQLException {
	List res = new ArrayList();
	PreparedStatement ps = con.prepareStatement("select level,location,message,message2 from logs");
	try {
	    ResultSet rs = ps.executeQuery();
	    try {
		while (rs.next()) {
		    res.add(rs.getString(1) + "; " + rs.getString(2) + "; " + rs.getString(3) + "; " + rs.getString(4));
		}
	    } finally {
		rs.close();
	    }
	} finally {
	    ps.close();
	}
	return res;
    }
}
