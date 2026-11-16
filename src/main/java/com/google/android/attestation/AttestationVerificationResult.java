/* Copyright 2019, The Android Open Source Project, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.android.attestation;

import static com.google.common.base.Preconditions.checkArgument;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableList;
import com.google.errorprone.annotations.Immutable;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Immutable, single snapshot of a verified Android key attestation.
 *
 * <p>An instance bundles together the certificate chain and the parsed attestation record that
 * were validated as one unit. Both are exposed through read-only views, so a caller cannot mutate
 * the chain, the security levels, or any authorization field after verification and thereby change
 * the conclusion of the check. Parsing, chain verification, and every later read observe the same
 * snapshot.
 */
@AutoValue
@Immutable
public abstract class AttestationVerificationResult {

  /**
   * The verified certificate chain, ordered from the leaf attestation certificate at index zero up
   * to the trusted root. The returned list is immutable and detached from the caller's input.
   */
  @AutoValue.CopyAnnotations
  @SuppressWarnings("Immutable")
  public abstract ImmutableList<X509Certificate> certificateChain();

  /**
   * The attestation record parsed from the verified chain. The record is itself immutable and is
   * bound to the leaf certificate's public key.
   */
  public abstract ParsedAttestationRecord attestationRecord();

  /**
   * Verifies the given certificate chain and parses its attestation record into a single immutable
   * snapshot.
   *
   * <p>The input list is defensively copied, so later clearing or modifying it cannot affect the
   * returned result. Verification confirms that every certificate is currently valid and that each
   * certificate is signed by its predecessor, and it binds the parsed record's attested key to the
   * leaf certificate's public key so the record cannot be substituted for one from another chain.
   *
   * @throws CertificateException if the chain is empty or malformed, a certificate is expired, a
   *     signature does not verify, or the parsed record does not match the leaf certificate
   * @throws IOException if the attestation extension cannot be parsed
   */
  public static AttestationVerificationResult create(List<X509Certificate> certificates)
      throws CertificateException, IOException {
    checkArgument(
        certificates != null && !certificates.isEmpty(),
        "certificates must not be null or empty");
    // Take an immutable, detached snapshot of the caller's list before doing any verification, so
    // the chain that is verified is exactly the chain later exposed to callers.
    ImmutableList<X509Certificate> certificateChain = ImmutableList.copyOf(certificates);
    verifyCertificateChain(certificateChain);
    ParsedAttestationRecord attestationRecord =
        ParsedAttestationRecord.createParsedAttestationRecord(certificateChain);
    PublicKey leafPublicKey = certificateChain.get(0).getPublicKey();
    if (!attestationRecord.attestedKey().equals(leafPublicKey)) {
      throw new CertificateException(
          "Attestation record is not bound to the leaf certificate: the attested key does not "
              + "match the leaf certificate's public key.");
    }
    return new AutoValue_AttestationVerificationResult(certificateChain, attestationRecord);
  }

  private static void verifyCertificateChain(List<X509Certificate> certificates)
      throws CertificateException {
    X509Certificate parent = certificates.get(certificates.size() - 1);
    for (int i = certificates.size() - 1; i >= 0; i--) {
      X509Certificate certificate = certificates.get(i);
      try {
        // Verify that the certificate has not expired or otherwise become invalid.
        certificate.checkValidity();
        certificate.verify(parent.getPublicKey());
      } catch (InvalidKeyException
          | NoSuchAlgorithmException
          | NoSuchProviderException
          | SignatureException e) {
        throw new CertificateException(
            "Unable to verify the certificate chain at index " + i + ".", e);
      }
      parent = certificate;
    }
  }
}
