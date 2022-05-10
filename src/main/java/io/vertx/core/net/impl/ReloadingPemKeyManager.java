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

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.StandardConstants;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.SNIHostName;

import io.vertx.core.buffer.Buffer;
import io.vertx.core.impl.Arguments;
import io.vertx.core.impl.VertxInternal;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;

import java.net.Socket;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ReloadingPemKeyManager extends X509ExtendedKeyManager {

  private static final AtomicInteger threadCount = new AtomicInteger(0);
  private static final Logger log = LoggerFactory.getLogger(ReloadingPemKeyManager.class);

  private final VertxInternal vertx;
  private CopyOnWriteArrayList<Credential> credentials = new CopyOnWriteArrayList<>();
  private FileWatcher fileWatcher;

  public ReloadingPemKeyManager(VertxInternal vertx, List<String> certPaths, List<String> keyPaths,
      List<Buffer> certValues, List<Buffer> keyValues) throws Exception {
    this.vertx = vertx;

    Arguments.require((certPaths.size() == keyPaths.size()) && (certValues.size() == keyValues.size()),
        "Number of certificates and keys do not match");

    // Load the credentials from disk for the first time.
    Iterator<String> cpi = certPaths.iterator();
    Iterator<String> kpi = keyPaths.iterator();
    while (cpi.hasNext() && kpi.hasNext()) {
      credentials.add(new Credential(cpi.next(), kpi.next()));
    }

    // Create credentials objects for certificates given by value.
    Iterator<Buffer> cvi = certValues.iterator();
    Iterator<Buffer> kvi = keyValues.iterator();
    while (cvi.hasNext() && kvi.hasNext()) {
      credentials.add(new Credential(cvi.next(), kvi.next()));
    }

    List<Path> watched = Stream.of(certPaths, keyPaths)
        .flatMap(p -> p.stream())
        .map(Paths::get)
        .collect(Collectors.toList());

    fileWatcher = new FileWatcher(watched, changedPath -> {
      try {
        int i = 0;
        for (Credential c : credentials) {
          if (c.pathEquals(changedPath.toString())) {
            credentials.set(i, new Credential(c.certPath, c.keyPath));
          }
          i++;
        }
      } catch (Exception e) {
        log.error("Failed to reload certificates: " + e);
      }
    });
    new Thread(fileWatcher, "vert.x-certwatcher-thread-" + threadCount.getAndIncrement()).start();
  }

  @Override
  public String[] getClientAliases(String keyType, Principal[] issuers) {
    throw new UnsupportedOperationException(); // Client mode.
  }

  @Override
  public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
    throw new UnsupportedOperationException(); // Client mode.
  }

  @Override
  public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
    throw new UnsupportedOperationException(); // Client mode.
  }

  public String[] getServerAliases(String keyType, Principal[] issuers) {
    throw new UnsupportedOperationException(); // Select server certificate based on key type and list of issuers
                                               // recognized by the peer.
  }

  public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
    throw new UnsupportedOperationException(); // Netty does not use SSLSocket
  }

  public X509Certificate[] getCertificateChain(String alias) {
    // chooseEngineClientAlias() has set alias to DNS name from SNI extension in TLS
    // handshake extension.

    // No SNI: return the certificate which was loaded first.
    if (alias.isEmpty()) {
      return credentials.get(0).certificates;
    }

    // Find match for requested SNI hostname: return certificate that matched.
    for (Credential c : credentials) {
      if (c.getDnsNames().contains(alias)) {
        return c.certificates;
      }
    }
    // No match for requested SNI hostname: return the certificate which was loaded
    // first.
    return credentials.get(0).certificates;
  }

  public PrivateKey getPrivateKey(String alias) {
    // chooseEngineClientAlias() has set alias to DNS name from SNI extension in TLS
    // handshake extension.

    // No SNI: return the key which was loaded first.
    if (alias.isEmpty()) {
      return credentials.get(0).key;
    }

    // Find match for requested SNI hostname: return key associated to matching
    // certificate.
    for (Credential c : credentials) {
      if (c.getDnsNames().contains(alias)) {
        return c.key;
      }
    }

    // No match for requested SNI hostname: return the key which was loaded first.
    return credentials.get(0).key;
  }

  @Override
  public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
    // If TLS SNI extension is sent by client, return given SNI hostname as an
    // alias.
    ExtendedSSLSession session = (ExtendedSSLSession) engine.getHandshakeSession();
    for (SNIServerName name : session.getRequestedServerNames()) {
      if (name.getType() == StandardConstants.SNI_HOST_NAME) {
        return ((SNIHostName) name).getAsciiName();
      }
    }

    // No SNI.
    return "";
  }

  // Credential wraps the certificate (with chain) and associated private key.
  private class Credential {

    private final X509Certificate[] certificates;
    private final PrivateKey key;
    private List<String> dnsNames = new ArrayList<>();
    private final String certPath;
    private final String keyPath;

    Credential(String certPath, String keyPath) throws Exception {
      this.certPath = certPath;
      this.keyPath = keyPath;
      Buffer buf = vertx.fileSystem().readFileBlocking(certPath);
      certificates = KeyStoreHelper.loadCerts(buf);

      buf = vertx.fileSystem().readFileBlocking(keyPath);
      key = KeyStoreHelper.loadPrivateKey(buf);

      dnsNames.addAll(KeyStoreHelper.getDnsNames(certificates[0]));
    }

    Credential(Buffer certValue, Buffer keyValue) throws Exception {
      certPath = "";
      keyPath = "";
      certificates = KeyStoreHelper.loadCerts(certValue);
      key = KeyStoreHelper.loadPrivateKey(keyValue);

      dnsNames.addAll(KeyStoreHelper.getDnsNames(certificates[0]));
    }

    public List<String> getDnsNames() {
      return dnsNames;
    }

    public boolean pathEquals(String filePath) {
      return certPath.equals(filePath) || keyPath.equals(filePath);
    }
  }
}
