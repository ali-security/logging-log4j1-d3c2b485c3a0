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

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.log4j.helpers.PatternConverter;
import org.apache.log4j.helpers.PatternParser;
import org.apache.log4j.spi.LoggingEvent;

/**
 * Turns the SQL statement of {@link JDBCAppender} into a parameterized
 * statement: every '...' string literal that contains a conversion pattern
 * is replaced by a bind variable whose value is formatted from the logging
 * event, so that event data is never interpreted as SQL (CVE-2022-23305).
 */
class JdbcPatternParser {
  private static final String QUESTION_MARK = "?";

  private static final char PERCENT_CHAR = '%';

  // NOTE: a capturing group seems to work just as well.
  // However, the atomic group is needed here to prevent StackOverflowError
  // See https://bugs.java.com/bugdatabase/view_bug.do?bug_id=6337993
  private static final Pattern STRING_LITERAL_PATTERN =
    Pattern.compile("'((?>[^']|'')+)'");

  private String lastPattern;
  private String parameterizedSql;
  private final List patternStringRepresentationList = new ArrayList();
  private final List args = new ArrayList();

  JdbcPatternParser() {
  }

  JdbcPatternParser(String insertString) {
    setPattern(insertString);
  }

  String getParameterizedSql() {
    return parameterizedSql;
  }

  List getUnmodifiablePatternStringRepresentationList() {
    return Collections.unmodifiableList(patternStringRepresentationList);
  }

  public String toString() {
    return "JdbcPatternParser{sql=" + parameterizedSql + ",args="
      + patternStringRepresentationList + "}";
  }

  /**
   * Converts '....' literals into bind variables in JDBC.
   */
  void setPattern(String pattern) {
    if (pattern == null) {
      throw new IllegalArgumentException("Null pattern");
    }
    if (pattern.equals(lastPattern)) {
      return;
    }
    Matcher m = STRING_LITERAL_PATTERN.matcher(pattern);
    StringBuffer sb = new StringBuffer();
    patternStringRepresentationList.clear();
    args.clear();
    while (m.find()) {
      String literal = m.group(1);
      if (literal.indexOf(PERCENT_CHAR) == -1) {
        // Just literal, append it as is
        // It can't contain user-provided parts like %m, etc.
        m.appendReplacement(sb, "'$1'");
        continue;
      }

      // Replace with bind
      m.appendReplacement(sb, QUESTION_MARK);
      // We will use prepared statements, so we don't need to escape quotes.
      // And we assume the users had 'That''s a string with quotes' in their configs.
      literal = literal.replaceAll("''", "'");
      patternStringRepresentationList.add(literal);
      args.add(new PatternParser(literal).parse());
    }
    m.appendTail(sb);
    parameterizedSql = sb.toString();
    lastPattern = pattern;
  }

  void setParameters(PreparedStatement ps, LoggingEvent logEvent)
    throws SQLException {
    for (int i = 0; i < args.size(); i++) {
      PatternConverter head = (PatternConverter) args.get(i);
      ps.setString(i + 1, buildValueStr(logEvent, head));
    }
  }

  private static String buildValueStr(LoggingEvent logEvent,
                                      PatternConverter head) {
    StringBuffer buffer = new StringBuffer();
    PatternConverter c = head;
    while (c != null) {
      c.format(buffer, logEvent);
      c = c.next;
    }
    return buffer.toString();
  }
}
