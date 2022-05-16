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

import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.attribute.FileTime;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Stream;

import io.vertx.core.buffer.Buffer;
import io.vertx.core.impl.VertxInternal;
import io.vertx.core.impl.logging.Logger;
import io.vertx.core.impl.logging.LoggerFactory;

public class ReloadingKeyStoreKeyManager extends ReloadingKeyManager {

  private static final Logger log = LoggerFactory.getLogger(ReloadingKeyStoreKeyManager.class);

  private final VertxInternal vertx;
  private final String type;
  private final String provider;
  private final String path;
  private final String password;
  private FileTime lastModified;

  public ReloadingKeyStoreKeyManager(VertxInternal vertx, String type, String provider, String path, String password) throws Exception {
    this.vertx = vertx;
    this.type = type;
    this.provider = provider;
    this.path = path;
    this.password = password;

    refresh();
  }

  void refresh() throws Exception {
    // If keystore has been previously loaded, check the modification timestamp to decide if reload is needed.
    if ((lastModified != null) && (lastModified.compareTo(Files.getLastModifiedTime(Paths.get(path))) > 0)) {
      // File was not modified since last reload.
      return;
    }

    // Load keystore from disk.
    Supplier<Buffer> value;
    value = () -> vertx.fileSystem().readFileBlocking(path);
    KeyStore ks = KeyStoreHelper.loadKeyStore(type, provider, password, value, null);
    this.lastModified = Files.getLastModifiedTime(Paths.get(path));

    // Read certificates and keys from the keystore.
    List<Credential> creds = new ArrayList<>();
    List<String> aliases = Collections.list(ks.aliases());
    Collections.sort(aliases);
    for (String alias : aliases) {
      if (ks.isKeyEntry(alias)) {
        PrivateKey key = (PrivateKey) ks.getKey(alias, password != null ? password.toCharArray() : null);
        X509Certificate[] certs = Stream.of(ks.getCertificateChain(alias)).map(X509Certificate.class::cast).toArray(X509Certificate[]::new);
        creds.add(new Credential(certs, key));
      }
    }
    setCredentials(creds);
  }

}
