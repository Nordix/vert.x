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

import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;

public class FileWatcher implements Runnable, Closeable {

  private static final Logger log = LoggerFactory.getLogger(FileWatcher.class);

  private WatchService watchService;
  private List<Path> notifyOnPaths;
  private Runnable callback;
  private volatile boolean close = false;

  public FileWatcher(List<Path> paths, Runnable callback) {
    this.notifyOnPaths = paths;
    this.callback = callback;

    try {
      watchService = FileSystems.getDefault().newWatchService();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }

    // Instead of watching the files themselves, watch moves in the parent directory
    // to catch the "atomic swap" of the files.
    paths.stream().map(Path::getParent).distinct().forEach(p -> {
      try {
        p.register(watchService, StandardWatchEventKinds.ENTRY_MODIFY);
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    });
  }

  @Override
  public void run() {
    do {
      try {
        final WatchKey key = watchService.take();
        if (key != null) {
          Path dir = (Path) key.watchable();
          for (WatchEvent<?> event : key.pollEvents()) {
            // Check if the move event was for a file that we follow.
            Path fullPath = dir.resolve((Path) event.context());
            if (notifyOnPaths.contains(fullPath)) {
              callback.run();
              break;
            }
          }
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
}
