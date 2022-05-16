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

import io.vertx.core.VertxException;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.impl.VertxInternal;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class ReloadingPemKeyManager extends ReloadingKeyManager {

  private static final Logger log = LoggerFactory.getLogger(ReloadingPemKeyManager.class);

  private final VertxInternal vertx;

  public ReloadingPemKeyManager(VertxInternal vertx, List<String> certPaths, List<String> keyPaths,
      List<Buffer> certValues, List<Buffer> keyValues) throws Exception {
    this.vertx = vertx;

    if ((keyPaths.size() < certPaths.size()) || (keyValues.size() < certValues.size())) {
      throw new VertxException("Missing private key");
    } else if ((keyPaths.size() > certPaths.size()) || (keyValues.size() > certValues.size())) {
      throw new VertxException("Missing X.509 certificate");
    } else if (keyPaths.isEmpty() && keyValues.isEmpty()) {
      throw new VertxException("No credentials configured");
    }

    List<Credential> creds = new ArrayList<>();

    // Load credentials that were passed as file paths.
    Iterator<String> cpi = certPaths.iterator();
    Iterator<String> kpi = keyPaths.iterator();
    while (cpi.hasNext() && kpi.hasNext()) {
      creds.add(new FileCredential(cpi.next(), kpi.next()));
    }

    // Create credentials that were passed by value.
    Iterator<Buffer> cvi = certValues.iterator();
    Iterator<Buffer> kvi = keyValues.iterator();
    while (cvi.hasNext() && kvi.hasNext()) {
      creds.add(new Credential(KeyStoreHelper.loadCerts(cvi.next()), KeyStoreHelper.loadPrivateKey(kvi.next())));
    }

    setCredentials(creds);
  }

  void refresh() {
    List<Credential> creds = new ArrayList<>(getCredentials());
    int i = 0;
    for (Credential c : creds) {
      if (c instanceof FileCredential) {
        try {
          FileCredential fc = (FileCredential) c;
          if (fc.needsReload()) {
            creds.set(i, new FileCredential(fc.certPath, fc.keyPath));
          }
        } catch (Exception e) {
          log.error("Failed to reload: " + e);
        }
      }
      i++;
    }

    setCredentials(creds);
  }

  // FileCredential wraps the certificate (with chain) and associated private key, loaded from file.
  class FileCredential extends Credential {

    private final String certPath;
    private final String keyPath;
    private final FileTime certLastModified;
    private final FileTime keyLastModified;

    FileCredential(String certPath, String keyPath) throws Exception {
      this.certPath = certPath;
      this.keyPath = keyPath;

      Buffer buf = vertx.fileSystem().readFileBlocking(certPath);
      certificates = KeyStoreHelper.loadCerts(buf);

      buf = vertx.fileSystem().readFileBlocking(keyPath);
      key = KeyStoreHelper.loadPrivateKey(buf);

      this.certLastModified = Files.getLastModifiedTime(Paths.get(certPath));
      this.keyLastModified = Files.getLastModifiedTime(Paths.get(keyPath));

      updateDnsNames();
    }

    boolean needsReload() throws Exception {
      return (certLastModified.compareTo(Files.getLastModifiedTime(Paths.get(certPath))) < 0) ||
          (keyLastModified.compareTo(Files.getLastModifiedTime(Paths.get(keyPath))) < 0);
    }
  }
}
