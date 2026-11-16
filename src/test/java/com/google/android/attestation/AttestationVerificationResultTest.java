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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.android.attestation.AuthorizationList.UserAuthType;
import com.google.android.attestation.ParsedAttestationRecord.SecurityLevel;
import com.google.protobuf.ByteString;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

/** Tests for the immutable {@link AttestationVerificationResult} verification boundary. */
@RunWith(JUnit4.class)
public final class AttestationVerificationResultTest {

  private static final X500Name CA_NAME = new X500Name("CN=Test Attestation CA");
  private static final X500Name INTERMEDIATE_NAME = new X500Name("CN=Test Attestation Sub CA");
  private static final X500Name LEAF_NAME = new X500Name("CN=Android Keystore Key");
  private static final ByteString CHALLENGE = ByteString.copyFromUtf8("challenge");
  private static final int ATTESTATION_VERSION = 3;
  private static final int UNKNOWN_TAG = 900;
  private static final AtomicInteger SERIAL_NUMBER = new AtomicInteger(1);

  private static KeyPair generateEcKeyPair() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(256);
    return generator.generateKeyPair();
  }

  private static X509Certificate createCertificate(
      PublicKey subjectPublicKey,
      KeyPair issuerKeyPair,
      X500Name issuerName,
      X500Name subjectName,
      boolean isCa,
      byte[] attestationExtensionBytes)
      throws Exception {
    X509v3CertificateBuilder builder =
        new JcaX509v3CertificateBuilder(
            issuerName,
            java.math.BigInteger.valueOf(SERIAL_NUMBER.getAndIncrement()),
            java.util.Date.from(java.time.Instant.now().minus(1, java.time.temporal.ChronoUnit.DAYS)),
            java.util.Date.from(java.time.Instant.now().plus(1, java.time.temporal.ChronoUnit.DAYS)),
            subjectName,
            subjectPublicKey);
    builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
    if (attestationExtensionBytes != null) {
      builder.addExtension(
          new org.bouncycastle.asn1.ASN1ObjectIdentifier(Constants.KEY_DESCRIPTION_OID),
          false,
          attestationExtensionBytes);
    }
    ContentSigner signer =
        new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeyPair.getPrivate());
    return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
  }

  private static ParsedAttestationRecord buildRecord(
      PublicKey attestedKey, AuthorizationList teeEnforced) {
    return ParsedAttestationRecord.builder()
        .setAttestationVersion(ATTESTATION_VERSION)
        .setAttestationSecurityLevel(SecurityLevel.TRUSTED_ENVIRONMENT)
        .setKeymasterVersion(4)
        .setKeymasterSecurityLevel(SecurityLevel.TRUSTED_ENVIRONMENT)
        .setAttestationChallenge(CHALLENGE)
        .setTeeEnforced(teeEnforced)
        .setAttestedKey(attestedKey)
        .build();
  }

  private static byte[] encodeExtension(ParsedAttestationRecord record) throws Exception {
    return record.toAsn1Sequence().getEncoded();
  }

  /** A self-consistent leaf + CA pair whose leaf carries a key attestation extension. */
  private static final class TestChain {
    final KeyPair caKeyPair;
    final KeyPair leafKeyPair;
    final X509Certificate caCert;
    final X509Certificate leafCert;
    final ParsedAttestationRecord record;

    TestChain(AuthorizationList teeEnforced) throws Exception {
      caKeyPair = generateEcKeyPair();
      leafKeyPair = generateEcKeyPair();
      caCert =
          createCertificate(
              caKeyPair.getPublic(), caKeyPair, CA_NAME, CA_NAME, true, null);
      record = buildRecord(leafKeyPair.getPublic(), teeEnforced);
      leafCert =
          createCertificate(
              leafKeyPair.getPublic(),
              caKeyPair,
              CA_NAME,
              LEAF_NAME,
              false,
              encodeExtension(record));
    }

    List<X509Certificate> certs() {
      return Arrays.asList(leafCert, caCert);
    }
  }

  @Test
  public void create_verifiesChainAndBindsRecordToSnapshot() throws Exception {
    AuthorizationList teeEnforced =
        AuthorizationList.builder().addUserAuthType(UserAuthType.FINGERPRINT).build();
    TestChain chain = new TestChain(teeEnforced);

    AttestationVerificationResult result =
        AttestationVerificationResult.create(chain.certs());

    assertThat(result.certificateChain())
        .containsExactly(chain.leafCert, chain.caCert)
        .inOrder();
    ParsedAttestationRecord record = result.attestationRecord();
    assertThat(record.attestationVersion()).isEqualTo(ATTESTATION_VERSION);
    assertThat(record.attestationSecurityLevel()).isEqualTo(SecurityLevel.TRUSTED_ENVIRONMENT);
    assertThat(record.keymasterSecurityLevel()).isEqualTo(SecurityLevel.TRUSTED_ENVIRONMENT);
    assertThat(record.attestationChallenge()).isEqualTo(CHALLENGE);
    assertThat(record.attestedKey()).isEqualTo(chain.leafCert.getPublicKey());
    assertThat(record.teeEnforced().userAuthType()).containsExactly(UserAuthType.FINGERPRINT);
  }

  @Test
  public void create_returnsImmutableSnapshotOfTheChain() throws Exception {
    TestChain chain = new TestChain(AuthorizationList.builder().build());
    List<X509Certificate> mutableInput = new ArrayList<>(chain.certs());

    AttestationVerificationResult result = AttestationVerificationResult.create(mutableInput);
    mutableInput.clear();

    // The snapshot is detached from the caller's list and cannot be mutated through it.
    assertThat(result.certificateChain())
        .containsExactly(chain.leafCert, chain.caCert)
        .inOrder();
    List<X509Certificate> exposedChain = result.certificateChain();
    assertThrows(
        UnsupportedOperationException.class,
        () -> mutate(exposedChain, chain.caCert));
  }

  @SuppressWarnings("DoNotCall")
  private static void mutate(List<X509Certificate> chain, X509Certificate certificate) {
    chain.add(certificate);
  }

  @Test
  public void create_rejectsChainWithInvalidSignature() throws Exception {
    TestChain chain = new TestChain(AuthorizationList.builder().build());
    KeyPair rogueIssuer = generateEcKeyPair();
    X509Certificate rogueLeaf =
        createCertificate(
            chain.leafKeyPair.getPublic(),
            rogueIssuer,
            CA_NAME,
            LEAF_NAME,
            false,
            encodeExtension(chain.record));

    assertThrows(
        CertificateException.class,
        () -> AttestationVerificationResult.create(Arrays.asList(rogueLeaf, chain.caCert)));
  }

  @Test
  public void create_rejectsRecordThatDoesNotMatchLeafKey() throws Exception {
    TestChain chain = new TestChain(AuthorizationList.builder().build());
    KeyPair otherKeyPair = generateEcKeyPair();
    ParsedAttestationRecord mismatchedRecord =
        buildRecord(otherKeyPair.getPublic(), AuthorizationList.builder().build());
    X509Certificate intermediate =
        createCertificate(
            otherKeyPair.getPublic(),
            chain.caKeyPair,
            CA_NAME,
            INTERMEDIATE_NAME,
            true,
            encodeExtension(mismatchedRecord));
    X509Certificate leaf =
        createCertificate(
            chain.leafKeyPair.getPublic(),
            otherKeyPair,
            INTERMEDIATE_NAME,
            LEAF_NAME,
            false,
            null);

    assertThrows(
        CertificateException.class,
        () ->
            AttestationVerificationResult.create(
                Arrays.asList(leaf, intermediate, chain.caCert)));
  }

  @Test
  public void create_retainsUnknownTagWithoutChangingModeledFields() throws Exception {
    ByteString unknownContent = ByteString.copyFrom(new ASN1Integer(42).getEncoded());
    AuthorizationList teeEnforced =
        AuthorizationList.builder()
            .addUserAuthType(UserAuthType.FINGERPRINT)
            .addUnknownField(UNKNOWN_TAG, unknownContent)
            .build();
    TestChain chain = new TestChain(teeEnforced);

    AttestationVerificationResult result = AttestationVerificationResult.create(chain.certs());
    AuthorizationList parsedTeeEnforced = result.attestationRecord().teeEnforced();

    assertThat(parsedTeeEnforced.unknownFields()).containsExactly(UNKNOWN_TAG, unknownContent);
    // The unknown entry must not alter any field that drives a security decision.
    assertThat(parsedTeeEnforced.userAuthType()).containsExactly(UserAuthType.FINGERPRINT);
    assertThat(result.attestationRecord().attestationSecurityLevel())
        .isEqualTo(SecurityLevel.TRUSTED_ENVIRONMENT);
    assertThat(result.attestationRecord().keymasterSecurityLevel())
        .isEqualTo(SecurityLevel.TRUSTED_ENVIRONMENT);
  }

  @Test
  public void unknownTag_roundTripsThroughAsn1() throws Exception {
    ByteString unknownContent = ByteString.copyFrom(new ASN1Integer(42).getEncoded());
    AuthorizationList original =
        AuthorizationList.builder()
            .addUserAuthType(UserAuthType.FINGERPRINT)
            .addUnknownField(UNKNOWN_TAG, unknownContent)
            .build();

    ASN1Encodable[] encoded = original.toAsn1Sequence().toArray();
    AuthorizationList reparsed =
        AuthorizationList.createAuthorizationList(encoded, ATTESTATION_VERSION);

    assertThat(reparsed.unknownFields()).containsExactly(UNKNOWN_TAG, unknownContent);
    assertThat(reparsed.userAuthType()).containsExactly(UserAuthType.FINGERPRINT);
    // The retained unknown entry must be byte-for-byte stable across re-encoding.
    assertThat(reparsed.toAsn1Sequence().getEncoded("DER"))
        .isEqualTo(original.toAsn1Sequence().getEncoded("DER"));
  }

  @Test
  public void unknownTag_isTrackedIndependentlyFromUnorderedTags() throws Exception {
    ByteString unknownContent = ByteString.copyFrom(new ASN1Integer(42).getEncoded());
    AuthorizationList original =
        AuthorizationList.builder()
            .addUserAuthType(UserAuthType.FINGERPRINT)
            .addUnknownField(UNKNOWN_TAG, unknownContent)
            .build();

    // Put the unknown tag before a modeled tag so ordering detection has something to observe.
    org.bouncycastle.asn1.ASN1Encodable[] encoded = original.toAsn1Sequence().toArray();
    org.bouncycastle.asn1.ASN1Encodable unknown = encoded[encoded.length - 1];
    System.arraycopy(encoded, 0, encoded, 1, encoded.length - 1);
    encoded[0] = unknown;

    AuthorizationList reparsed =
        AuthorizationList.createAuthorizationList(encoded, ATTESTATION_VERSION);

    assertThat(reparsed.unknownFields()).containsExactly(UNKNOWN_TAG, unknownContent);
    assertThat(reparsed.userAuthType()).containsExactly(UserAuthType.FINGERPRINT);
    // The displaced unknown entry is still flagged as out of order by the existing ordering logic;
    // tracking it as unknown does not suppress the unordered-tag signal.
    assertThat(reparsed.unorderedTags()).contains(UNKNOWN_TAG);
  }

  @Test
  public void create_rejectsEmptyChain() {
    assertThrows(
        IllegalArgumentException.class,
        () -> AttestationVerificationResult.create(new ArrayList<>()));
  }

  @Test
  public void create_rejectsNullChain() {
    assertThrows(
        IllegalArgumentException.class, () -> AttestationVerificationResult.create(null));
  }
}
