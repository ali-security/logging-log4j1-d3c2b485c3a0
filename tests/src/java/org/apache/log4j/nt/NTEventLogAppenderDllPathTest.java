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

package org.apache.log4j.nt;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.StringTokenizer;

import junit.framework.TestCase;
import org.apache.log4j.LogManager;


/**
 * Tests of how NTEventLogAppender locates its DLL through the
 * log4j.nteventlog.dll.path system property.
 */
public class NTEventLogAppenderDllPathTest extends TestCase {

  /**
   * Absolute path of the native library supplied through the DLL path
   * property while NTEventLogAppender was initialized, or null if none was.
   */
  private static String configuredLibrary;

  /**
   * Error thrown while initializing NTEventLogAppender, or null on success.
   */
  private static Throwable initError;

  static {
    initializeAppender();
  }

  private String originalDllPath;

  public void setUp() {
    originalDllPath = System.getProperty(NTEventLogAppender.DLL_PATH_PROPERTY);
    System.getProperties().remove(NTEventLogAppender.DLL_PATH_PROPERTY);
  }

  public void tearDown() {
    if (originalDllPath != null) {
      System.setProperty(NTEventLogAppender.DLL_PATH_PROPERTY, originalDllPath);
    } else {
      System.getProperties().remove(NTEventLogAppender.DLL_PATH_PROPERTY);
    }
    LogManager.shutdown();
  }

  /**
   * Initializes NTEventLogAppender, whose static initializer loads the native
   * library.  On Windows the NTEventLogAppender DLL is found as before.
   * Elsewhere no NTEventLogAppender library exists, so the absolute path of
   * the C library already mapped into this JVM is supplied through the DLL
   * path property: the class then only initializes if that configured
   * absolute path is loaded with System.load.
   */
  private static void initializeAppender() {
    String original = System.getProperty(NTEventLogAppender.DLL_PATH_PROPERTY);
    if (original == null) {
      configuredLibrary = findMappedCLibrary();
      if (configuredLibrary != null) {
        System.setProperty(NTEventLogAppender.DLL_PATH_PROPERTY, configuredLibrary);
      }
    }
    try {
      Class.forName("org.apache.log4j.nt.NTEventLogAppender");
    } catch (Throwable t) {
      initError = t;
    } finally {
      if (original == null) {
        System.getProperties().remove(NTEventLogAppender.DLL_PATH_PROPERTY);
      }
    }
  }

  /**
   * Returns the absolute path of the C library mapped into this process,
   * read from /proc/self/maps, or null when it cannot be determined.
   */
  private static String findMappedCLibrary() {
    File maps = new File("/proc/self/maps");
    if (!maps.exists()) {
      return null;
    }
    BufferedReader reader = null;
    try {
      reader = new BufferedReader(new FileReader(maps));
      String line;
      while ((line = reader.readLine()) != null) {
        int slash = line.indexOf('/');
        if (slash < 0) {
          continue;
        }
        File lib = new File(line.substring(slash).trim());
        String name = lib.getName();
        if ((name.startsWith("libc.so") || name.startsWith("libc-"))
            && name.indexOf(".so") > 0 && lib.isFile()) {
          return lib.getAbsolutePath();
        }
      }
    } catch (IOException e) {
      return null;
    } finally {
      if (reader != null) {
        try {
          reader.close();
        } catch (IOException e) {
        }
      }
    }
    return null;
  }

  /**
   * Returns true if the named library can be found on java.library.path.
   */
  private static boolean isOnLibraryPath(String libName) {
    String libraryPath = System.getProperty("java.library.path");
    if (libraryPath == null) {
      return false;
    }
    String fileName = System.mapLibraryName(libName);
    StringTokenizer dirs = new StringTokenizer(libraryPath, File.pathSeparator);
    while (dirs.hasMoreTokens()) {
      if (new File(dirs.nextToken(), fileName).exists()) {
        return true;
      }
    }
    return false;
  }

  /**
   * When the DLL path property names an existing library by absolute path,
   * the appender must load that file with System.load instead of searching
   * the PATH and java.library.path, where a planted DLL could be picked up.
   * No NTEventLogAppender library is on the library path here, so the
   * appender can only initialize if the configured absolute path was loaded.
   * On Windows the appender is initialized from the installed DLL instead.
   */
  public void testConfiguredAbsoluteDllPathIsLoaded() {
    if (configuredLibrary == null) {
      return;
    }
    assertFalse(isOnLibraryPath("NTEventLogAppender"));
    assertFalse(isOnLibraryPath("NTEventLogAppender." + System.getProperty("os.arch")));
    if (initError != null) {
      fail("NTEventLogAppender did not load the DLL configured as "
          + configuredLibrary + ": " + initError);
    }
  }

  /**
   * When the system property is not set, resolveConfiguredDllPath should return null.
   */
  public void testResolveConfiguredDllPath_notSet() {
    System.getProperties().remove(NTEventLogAppender.DLL_PATH_PROPERTY);
    assertNull(NTEventLogAppender.resolveConfiguredDllPath());
  }

  /**
   * When the system property is an empty string, resolveConfiguredDllPath should return null.
   */
  public void testResolveConfiguredDllPath_emptyString() {
    System.setProperty(NTEventLogAppender.DLL_PATH_PROPERTY, "");
    assertNull(NTEventLogAppender.resolveConfiguredDllPath());
  }

  /**
   * When the system property is whitespace only, resolveConfiguredDllPath should return null.
   */
  public void testResolveConfiguredDllPath_whitespaceOnly() {
    System.setProperty(NTEventLogAppender.DLL_PATH_PROPERTY, "   ");
    assertNull(NTEventLogAppender.resolveConfiguredDllPath());
  }

  /**
   * When the system property is a relative path, resolveConfiguredDllPath should return null.
   */
  public void testResolveConfiguredDllPath_relativePath() {
    System.setProperty(NTEventLogAppender.DLL_PATH_PROPERTY, "relative/path/NTEventLogAppender.dll");
    assertNull(NTEventLogAppender.resolveConfiguredDllPath());
  }

  /**
   * A relative path resolves against the working directory, where a DLL
   * may have been planted, so it must be rejected even when the file exists.
   */
  public void testResolveConfiguredDllPath_relativePathToExistingFile() throws IOException {
    File planted = File.createTempFile("NTEventLogAppender", ".dll",
        new File(System.getProperty("user.dir")));
    planted.deleteOnExit();
    try {
      String relativePath = planted.getName();
      assertTrue(new File(relativePath).exists());
      System.setProperty(NTEventLogAppender.DLL_PATH_PROPERTY, relativePath);
      assertNull(NTEventLogAppender.resolveConfiguredDllPath());
    } finally {
      planted.delete();
    }
  }

  /**
   * When the system property is an absolute path to a file that does not exist,
   * resolveConfiguredDllPath should return null.
   */
  public void testResolveConfiguredDllPath_absoluteButMissing() {
    String missingPath = new File(System.getProperty("java.io.tmpdir"), "no_such_NTEventLogAppender.dll")
        .getAbsolutePath();
    System.setProperty(NTEventLogAppender.DLL_PATH_PROPERTY, missingPath);
    assertNull(NTEventLogAppender.resolveConfiguredDllPath());
  }

  /**
   * When the system property is an absolute path to an existing file,
   * resolveConfiguredDllPath should return that absolute path.
   */
  public void testResolveConfiguredDllPath_absoluteAndExists() throws IOException {
    File tempFile = File.createTempFile("NTEventLogAppender", ".dll");
    tempFile.deleteOnExit();
    try {
      String absolutePath = tempFile.getAbsolutePath();
      System.setProperty(NTEventLogAppender.DLL_PATH_PROPERTY, absolutePath);
      String result = NTEventLogAppender.resolveConfiguredDllPath();
      assertNotNull(result);
      assertEquals(absolutePath, result);
    } finally {
      tempFile.delete();
    }
  }
}
