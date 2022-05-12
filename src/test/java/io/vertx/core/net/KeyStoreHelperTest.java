/*
 * Copyright (c) 2011-2019 Contributors to the Eclipse Foundation
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
 * which is available at https://www.apache.org/licenses/LICENSE-2.0.
 *
 * SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
 */


package io.vertx.core.net;

import static org.hamcrest.CoreMatchers.instanceOf;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Enumeration;

import javax.net.ssl.X509KeyManager;

import io.vertx.core.net.impl.KeyStoreHelper;
import io.vertx.test.core.VertxTestBase;
import org.junit.Assume;
import org.junit.Test;

import io.vertx.core.impl.VertxInternal;
import io.vertx.core.net.PemKeyCertOptions;


/**
 * Verifies behavior of {@link KeyStoreHelper}.
 *
 */
public class KeyStoreHelperTest extends VertxTestBase {

  /**
   * Verifies that the key store helper can read a PKCS#8 encoded RSA private key
   * from a PEM file.
   *
   * @throws Exception if the key cannot be read.
   */
  @Test
  public void testKeyStoreHelperSupportsRSAPrivateKeys() throws Exception {
    PemKeyCertOptions options = new PemKeyCertOptions()
            .addKeyPath("target/test-classes/tls/server-key.pem")
            .addCertPath("target/test-classes/tls/server-cert.pem");
    assertKeyType(options.getKeyManager(vertx), RSAPrivateKey.class);
  }

  /**
   * Verifies that the key store helper can read a PKCS#8 encoded EC private key
   * from a PEM file.
   *
   * @throws Exception if the key cannot be read.
   */
  @Test
  public void testKeyStoreHelperSupportsECPrivateKeys() throws Exception {

    Assume.assumeTrue("ECC is not supported by VM's security providers", isECCSupportedByVM());
    PemKeyCertOptions options = new PemKeyCertOptions()
            .addKeyPath("target/test-classes/tls/server-key-ec.pem")
            .addCertPath("target/test-classes/tls/server-cert-ec.pem");
    assertKeyType(options.getKeyManager(vertx), ECPrivateKey.class);
  }

  private void assertKeyType(X509KeyManager km, Class<?> expectedKeyType) throws KeyStoreException, GeneralSecurityException {
    assertThat(km.getPrivateKey(""), instanceOf(expectedKeyType));
    assertThat(km.getCertificateChain("")[0], instanceOf(X509Certificate.class));
  }

  private boolean isECCSupportedByVM() {
    try {
      KeyFactory.getInstance("EC");
      return true;
    } catch (GeneralSecurityException e) {
        return false;
    }
  }
}
