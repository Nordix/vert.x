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

import javax.net.ssl.X509ExtendedKeyManager;

import io.vertx.core.buffer.Buffer;
import io.vertx.core.impl.VertxInternal;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;

import java.net.Socket;
import java.nio.file.Paths;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLEngine;

public class ReloadingKeyManager extends X509ExtendedKeyManager {

  private static final AtomicInteger threadCount = new AtomicInteger(0);
  private static final Logger log = LoggerFactory.getLogger(ReloadingKeyManager.class);

  // Credentials wraps the certificate (with chain) and associated private key.
  private class Credentials {
    private final X509Certificate[] certificates;
    private final PrivateKey key;

    Credentials(PrivateKey key, X509Certificate[] certificates) {
      this.key = key;
      this.certificates = certificates;
    }
  }
  private final AtomicReference<Credentials> credentials = new AtomicReference<>();

  private final VertxInternal vertx;
  private final String keyPath;
  private final String certPath;
  private List<String> dnsNames;
  private FileWatcher fileWatcher;

  ReloadingKeyManager(VertxInternal vertx, String keyPath, String certPath) throws Exception {
    this.vertx = vertx;
    this.keyPath = vertx.resolveFile(keyPath).getAbsolutePath();
    this.certPath = vertx.resolveFile(certPath).getAbsolutePath();
    this.dnsNames = new ArrayList<>();

    // Load the credentials for the first time.
    loadCredentials();

    // Set up a file change watcher that reloads the credentials when they change.
    fileWatcher = new FileWatcher(Arrays.asList(Paths.get(this.keyPath), Paths.get(this.certPath)), () -> {
      try {
        loadCredentials();
      } catch (Exception e) {
        log.error("Failed to reload certificates: " + e);
      }
    });
    new Thread(fileWatcher, "vert.x-certwatcher-thread-" + threadCount.getAndIncrement()).start();
  }

  public String[] getClientAliases(String keyType, Principal[] issuers) {
    throw new UnsupportedOperationException();
  }

  public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
    // We only have single certificate and key, nothing to choose from, so return fixed value.
    return "";
  }

  public String[] getServerAliases(String keyType, Principal[] issuers) {
    throw new UnsupportedOperationException();
  }

  public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
    // We only have single certificate and key, nothing to choose from, so return fixed value.
    return "";
  }

  public X509Certificate[] getCertificateChain(String alias) {
    return credentials.get().certificates;
  }

  public PrivateKey getPrivateKey(String alias) {
    return credentials.get().key;
  }

  @Override
  public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
    // We only have single certificate and key, so we do not have anything to choose from.
    return "";
  }

  @Override
  public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
    // We only have single certificate and key, so we do not have anything to choose from.
    return "";
  }

  public List<String> getDnsNames() {
    return dnsNames;
  }

  private void loadCredentials() throws Exception {
    Buffer buf = vertx.fileSystem().readFileBlocking(certPath);
    X509Certificate[] certificates = KeyStoreHelper.loadCerts(buf);

    // Collect the DNS names from the certificates.
    dnsNames.clear();
    for (X509Certificate cert : certificates) {
      dnsNames.addAll(KeyStoreHelper.getDnsNames(cert));
    }

    buf = vertx.fileSystem().readFileBlocking(keyPath);
    PrivateKey key = KeyStoreHelper.loadPrivateKey(buf);

    // New credentials were successfully loaded, so swap them to be used instead of the old ones.
    credentials.set(new Credentials(key, certificates));
  }
}
