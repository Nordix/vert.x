/*
* Copyright (c) 2011-2022 Contributors to the Eclipse Foundation
*
* This program and the accompanying materials are made available under the
* terms of the Eclipse Public License 2.0 which is available at
* http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
* which is available at https://www.apache.org/licenses/LICENSE-2.0.
*
* SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
*/

package io.vertx.core.net.impl;

import java.io.Closeable;
import java.io.IOException;
import java.nio.file.ClosedWatchServiceException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.List;
import java.util.function.Consumer;

import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;

public class FileWatcher implements Runnable, Closeable {

  private static final Logger log = LoggerFactory.getLogger(FileWatcher.class);

  private WatchService watchService;
  private List<Path> notifyOnPaths;
  private Consumer<Path> callback;
  private volatile boolean close = false;

  public FileWatcher(List<Path> paths, Consumer<Path> callback) {
    this.notifyOnPaths = paths;
    this.callback = callback;

    try {
      watchService = FileSystems.getDefault().newWatchService();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }

    // Instead of watching the files we watch all moves in the parent directory:
    // given paths: /foo/bar/cert.pem and /foo/bar/pkey.pem
    // single watch will be assigned to directory: /foo/bar
    //
    // The approach works when simply moving new files in place, and with K8s secret mounts
    // which uses following symlink based approach to guarantee atomic change:
    //
    // Initial directory layout:
    //
    // /secret-mountpoint/file1                # symbolic link to ..data/file1
    // /secret-mountpoint/file2                # symbolic link to ..data/file2
    // /secret-mountpoint/..data               # symbolic link to ..timestamp-1
    // /secret-mountpoint/..timestamp-1        # directory
    // /secret-mountpoint/..timestamp-1/file1  # initial version of file1
    // /secret-mountpoint/..timestamp-1/file2  # initial version of file2
    //
    // New versions of files are created into directory ..timestamp-2 but not yet used
    //
    // /secret-mountpoint/file1                # symbolic link to ..data/file1
    // /secret-mountpoint/file2                # symbolic link to ..data/file2
    // /secret-mountpoint/..data               # symbolic link to ..timestamp-1
    // /secret-mountpoint/..timestamp-1        # directory
    // /secret-mountpoint/..timestamp-1/file1  # initial version of file1
    // /secret-mountpoint/..timestamp-1/file2  # initial version of file2
    // /secret-mountpoint/..timestamp-2        # new directory
    // /secret-mountpoint/..timestamp-2/file1  # new version of file1
    // /secret-mountpoint/..timestamp-2/file2  # new version of file2
    //
    // To take new files into use, atomic update of symlink ..data is performed:
    //
    // /secret-mountpoint/file1                # symbolic link to ..data/file1
    // /secret-mountpoint/file2                # symbolic link to ..data/file2
    // /secret-mountpoint/..data               # symbolic link to ..timestamp-2
    // /secret-mountpoint/..timestamp-2        # new directory
    // /secret-mountpoint/..timestamp-2/file1  # new version of file1
    // /secret-mountpoint/..timestamp-2/file2  # new version of file2
    //
    // The move will trigger a watch event.
    paths.stream()
        .map(Path::getParent) // Watch parent directory of each file.
        .distinct() // Watch only unique directories.
        .forEach(p -> watch(p, watchService));
  }

  @Override
  public void run() {
    do {
      try {
        final WatchKey key = watchService.take();

        if (key != null) {
          Path dir = (Path) key.watchable();
          for (WatchEvent<?> event : key.pollEvents()) {
            Path fullPath = dir.resolve((Path) event.context());

            // Check if the move event was for a file that we follow.
            if (notifyOnPaths.contains(fullPath)) {
              // Notify that file changed.
              callback.accept(fullPath);
            }
          }
          key.reset();
        }
      } catch (InterruptedException e) {
        log.warn("Interrupted", e);
        Thread.currentThread().interrupt();
      } catch (ClosedWatchServiceException e) {
        break;
      }
    } while (!close);
  }

  @Override
  public void close() throws IOException {
    close = true;
    watchService.close();
  }

  static void watch(Path directory, WatchService ws) {
    try {
      directory.register(ws, StandardWatchEventKinds.ENTRY_MODIFY);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }
}
