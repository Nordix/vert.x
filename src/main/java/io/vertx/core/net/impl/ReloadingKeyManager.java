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

import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

public abstract class ReloadingKeyManager extends X509ExtendedKeyManager {

  private static final Logger log = LoggerFactory.getLogger(ReloadingKeyManager.class);

  // Defines how often the keystore file should be checked for changes
  final Duration cacheTtl = Duration.of(1, ChronoUnit.SECONDS);

  private AtomicReference<List<Credential>> credentials = new AtomicReference<>();
  private Instant cacheExpiredTime = Instant.MIN;

  abstract void refresh() throws Exception;

  private void refreshNoThrow() {
    // Has enough time passed for the keystore to be refreshed?
    if (Instant.now().isBefore(cacheExpiredTime)) {
      return;
    }

    // Set the next time when refresh should be checked for possible update.
    cacheExpiredTime = Instant.now().plus(cacheTtl);

    try {
      refresh();
    } catch (Exception e) {
      log.error("Failed to refresh: " + e);
    }
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

  @Override
  public String[] getServerAliases(String keyType, Principal[] issuers) {
    throw new UnsupportedOperationException();
  }

  @Override
  public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
    throw new UnsupportedOperationException();
  }

  @Override
  public X509Certificate[] getCertificateChain(String alias) {
    refreshNoThrow();
    // Alias is set by chooseEngineServerAlias() to the server name set by client in SNI extension or
    // to "" by chooseEngineClientAlias().

    if (alias == null) {
      return null;
    }

    // Return first loaded certificate if alias is an empty string.
    if (alias.isEmpty()) {
      return credentials.get().get(0).certificates;
    }

    // Find match for requested SNI hostname: return certificate that matched.
    for (Credential c : credentials.get()) {
      if (c.isDomainEqual(alias)) {
        return c.certificates;
      }
    }

    // No match for requested SNI hostname: return the certificate which was loaded first.
    return credentials.get().get(0).certificates;
  }

  @Override
  public PrivateKey getPrivateKey(String alias) {
    refreshNoThrow();

    // Alias is set by chooseEngineServerAlias() to the server name set by client in SNI extension or
    // to "" by chooseEngineClientAlias().

    if (alias == null) {
      return null;
    }

    // Return first loaded key if alias is an empty string.
    if (alias.isEmpty()) {
      return credentials.get().get(0).key;
    }

    // Find match for requested SNI hostname: return key that matched.
    for (Credential c : credentials.get()) {
      if (c.isDomainEqual(alias)) {
        return c.key;
      }
    }

    // No match for requested SNI hostname: return the key which was loaded first.
    return credentials.get().get(0).key;
  }

  List<Credential> getCredentials() {
    return credentials.get();
  }

  void setCredentials(List<Credential> credentials) {
    this.credentials.set(credentials);
  }

  /**
   * Credential wraps the certificate (with chain) and associated private key.
   */
  class Credential {
    X509Certificate[] certificates;
    PrivateKey key;
    List<String> dnsNames = new ArrayList<>();
    List<String> wildcardDnsNames = new ArrayList<>();

    Credential() {

    }

    Credential(X509Certificate[] certificates, PrivateKey key) throws Exception {
      this.certificates = certificates;
      this.key = key;
      updateDnsNames();
    }

    boolean isDomainEqual(String fqdn) {
      // Try matching domain name to certificate's DNS names.
      if (dnsNames.contains(fqdn)) {
        return true;
      } else if (!wildcardDnsNames.isEmpty()) {
        // Try to match subdomain.
        int index = fqdn.indexOf('.') + 1;
        if (index > 0 && wildcardDnsNames.contains(fqdn.substring(index))) {
          return true;
        }
      }
      return false;
    }

    protected void updateDnsNames() {
      for (String fqdn : KeyStoreHelper.getDnsNames(certificates[0])) {
        if (fqdn.startsWith("*.")) {
          wildcardDnsNames.add(fqdn.substring(2));
        } else {
          dnsNames.add(fqdn);
        }
      }
    }
  }

}
