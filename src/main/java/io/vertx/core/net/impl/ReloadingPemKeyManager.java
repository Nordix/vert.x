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

import io.vertx.core.VertxException;
import io.vertx.core.buffer.Buffer;
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
import java.util.Collection;
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

    if ((keyPaths.size() < certPaths.size()) || (keyValues.size() < certValues.size())) {
      throw new VertxException("Missing private key");
    } else if ((keyPaths.size() > certPaths.size()) || (keyValues.size() > certValues.size())) {
      throw new VertxException("Missing X.509 certificate");
    } else if (keyPaths.isEmpty() && keyValues.isEmpty()) {
      throw new VertxException("No credentials configured");
    }

    // Load credentials that were passed as file paths.
    Iterator<String> cpi = certPaths.iterator();
    Iterator<String> kpi = keyPaths.iterator();
    while (cpi.hasNext() && kpi.hasNext()) {
      credentials.add(new Credential(cpi.next(), kpi.next()));
    }

    // Create credentials that were passed by value.
    Iterator<Buffer> cvi = certValues.iterator();
    Iterator<Buffer> kvi = keyValues.iterator();
    while (cvi.hasNext() && kvi.hasNext()) {
      credentials.add(new Credential(cvi.next(), kvi.next()));
    }

    // Create list of watched Paths from strings.
    List<Path> watched = Stream.of(certPaths, keyPaths)
        .flatMap(Collection::stream)
        .map(Paths::get)
        .collect(Collectors.toList());

    // Start watching changes to the files.
    fileWatcher = new FileWatcher(watched, changedPath -> {
      try {
        // Re-create credential and thereby reload certificate and key when files change.
        int i = 0;
        for (Credential c : credentials) {
          if (c.pathEquals(changedPath.toString())) {
            log.info("Reloading: " + changedPath.toString());
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
  public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
    // Return empty string to signify we always use the first loaded credential as client credentials.
    return "";
  }

  @Override
  public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
    // If client sent TLS SNI, return the requested server name as alias, which will then be used to select
    // the one of the credentials in getCertificateChain() and getPrivateKey().
    ExtendedSSLSession session = (ExtendedSSLSession) engine.getHandshakeSession();
    for (SNIServerName name : session.getRequestedServerNames()) {
      if (name.getType() == StandardConstants.SNI_HOST_NAME) {
        return ((SNIHostName) name).getAsciiName();
      }
    }

    // Return empty string to signify that client did not ask for any particular server name,
    // and that we should use first loaded credential as server credentials.
    return "";
  }

  @Override
  public String[] getClientAliases(String keyType, Principal[] issuers) {
    throw new UnsupportedOperationException();
  }

  @Override
  public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
    throw new UnsupportedOperationException();
  }

  public String[] getServerAliases(String keyType, Principal[] issuers) {
    throw new UnsupportedOperationException();
  }

  public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
    throw new UnsupportedOperationException();
  }

  public X509Certificate[] getCertificateChain(String alias) {
    // Alias is set by chooseEngineServerAlias() to the server name set by client in SNI extension or
    // to "" by chooseEngineClientAlias().

    // Return first loaded certificate if alias is an empty string.
    if (alias.isEmpty()) {
      return credentials.get(0).certificates;
    }

    // Find match for requested SNI hostname: return certificate that matched.
    for (Credential c : credentials) {
      if (c.isDomainEqual(alias)) {
        return c.certificates;
      }
    }

    // No match for requested SNI hostname: return the certificate which was loaded first.
    return credentials.get(0).certificates;
  }

  public PrivateKey getPrivateKey(String alias) {
    // Alias is set by chooseEngineServerAlias() to the server name set by client in SNI extension or
    // to "" by chooseEngineClientAlias().

    // Return first loaded key if alias is an empty string.
    if (alias.isEmpty()) {
      return credentials.get(0).key;
    }

    // Find match for requested SNI hostname: return key that matched.
    for (Credential c : credentials) {
      if (c.isDomainEqual(alias)) {
        return c.key;
      }
    }

    // No match for requested SNI hostname: return the key which was loaded first.
    return credentials.get(0).key;
  }

  // Credential wraps the certificate (with chain) and associated private key.
  private class Credential {

    private final X509Certificate[] certificates;
    private final PrivateKey key;
    private List<String> dnsNames = new ArrayList<>();
    private List<String> wildcardDnsNames = new ArrayList<>();
    private final String certPath;
    private final String keyPath;

    Credential(String certPath, String keyPath) throws Exception {
      this.certPath = certPath;
      this.keyPath = keyPath;

      Buffer buf = vertx.fileSystem().readFileBlocking(certPath);
      certificates = KeyStoreHelper.loadCerts(buf);

      buf = vertx.fileSystem().readFileBlocking(keyPath);
      key = KeyStoreHelper.loadPrivateKey(buf);

      for (String fqdn : KeyStoreHelper.getDnsNames(certificates[0])) {
        if (fqdn.startsWith("*.")) {
          wildcardDnsNames.add(fqdn.substring(2));
        } else {
          dnsNames.add(fqdn);
        }
      }
    }

    Credential(Buffer certValue, Buffer keyValue) throws Exception {
      certPath = "";
      keyPath = "";
      certificates = KeyStoreHelper.loadCerts(certValue);
      key = KeyStoreHelper.loadPrivateKey(keyValue);

      dnsNames.addAll(KeyStoreHelper.getDnsNames(certificates[0]));
    }

    public boolean pathEquals(String filePath) {
      return certPath.equals(filePath) || keyPath.equals(filePath);
    }

    public boolean isDomainEqual(String fqdn) {
      // Try matching domain name to certificate's DNS names.
      if (dnsNames.contains(fqdn)) {
        return true;
      } else if (!wildcardDnsNames.isEmpty()) {
        // Try to match subdomain.
        int index = fqdn.indexOf('.') + 1;
        if (index > 0) {
          if (wildcardDnsNames.contains(fqdn.substring(index))) {
            return true;
          }
        }
      }
      return false;
    }
  }
}
