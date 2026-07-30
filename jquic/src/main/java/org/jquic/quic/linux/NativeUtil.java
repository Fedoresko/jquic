/*
 * Copyright 2026 Fedor Malyshev
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jquic.quic.linux;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InaccessibleObjectException;
import java.net.URL;
import java.nio.channels.DatagramChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

public class NativeUtil {
    public enum OS {
        WINDOWS,
        LINUX,
    }

    public static OS detectOs() {
        String os = System.getProperty("os.name").toLowerCase();
        String arch = System.getProperty("os.arch").toLowerCase();

        if (os.contains("linux") && (arch.contains("amd64") || arch.contains("x86_64"))) {
            return OS.LINUX;
        } else if (os.contains("win")) {
            return OS.WINDOWS;
        } else {
            throw new UnsupportedOperationException("Unsupported OS/Arch target mapping.");
        }
    }

    public static String getLibExt(OS os) {
        return switch (os) {
            case WINDOWS -> ".dll";
            case LINUX -> ".so";
        };
    }

    public static void loadLib(String libName) throws IOException {
        String filename = libName + getLibExt(detectOs());

        // 1. Java elegantly finds the resource relative to this class's package
        URL resourceUrl = NativeUtil.class.getResource("/"+filename);
        if (resourceUrl == null) {
            throw new FileNotFoundException("Cannot find native file in package: " + filename);
        }

        // 2. Extract out of the JAR archive to a temporary file
        Path tempLib = Files.createTempFile("native-", "-" + filename);
        tempLib.toFile().deleteOnExit();

        try (InputStream is = resourceUrl.openStream()) {
            Files.copy(is, tempLib, StandardCopyOption.REPLACE_EXISTING);
        }

        // 3. Load the native binary absolute path into the JVM
        System.load(tempLib.toAbsolutePath().toString());
    }

    /**
     * Cross-version reflection helper to extract native File Descriptors.
     * Compatible with Java 8, 11, and 17 LTS runtimes on Linux platforms.
     * <p>
     * Note: For Java 9+, you must add JVM arguments:
     * --add-opens java.base/sun.nio.ch=ALL-UNNAMED --add-opens java.base/java.io=ALL-UNNAMED
     */
    public static int getNativeFd(DatagramChannel channel) throws NoSuchFieldException, IllegalAccessException {
        try {
            Field fdField = channel.getClass().getDeclaredField("fd");
            fdField.setAccessible(true);
            Object fdObj = fdField.get(channel);

            Field intField = fdObj.getClass().getDeclaredField("fd");
            intField.setAccessible(true);
            return intField.getInt(fdObj);
        } catch (InaccessibleObjectException e) {
            throw new IllegalStateException(
                    "Cannot access file descriptor. Add JVM arguments: " +
                            "--add-opens java.base/sun.nio.ch=ALL-UNNAMED --add-opens java.base/java.io=ALL-UNNAMED", e);
        }
    }
}
