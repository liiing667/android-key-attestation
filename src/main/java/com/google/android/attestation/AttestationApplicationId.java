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

import static com.google.android.attestation.Constants.ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX;
import static com.google.android.attestation.Constants.ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX;
import static com.google.android.attestation.Constants.ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX;
import static com.google.android.attestation.Constants.ATTESTATION_PACKAGE_INFO_VERSION_INDEX;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableSet;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import com.google.protobuf.ByteString;
import java.io.IOException;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;

/**
 * This data structure reflects the Android platform's belief as to which apps are allowed to use
 * the secret key material under attestation. The ID can comprise multiple packages if and only if
 * multiple packages share the same UID.
 *
 * <p>The Attestation Application ID data from KeyMint will not exceed 1K bytes.
 */
@AutoValue
@Immutable
public abstract class AttestationApplicationId {
  public abstract ImmutableSet<AttestationPackageInfo> packageInfos();

  public abstract ImmutableSet<ByteString> signatureDigests();

  public abstract Builder toBuilder();

  public static Builder builder() {
    return new AutoValue_AttestationApplicationId.Builder();
  }

  /** Builder for {@link AttestationApplicationId}. */
  @AutoValue.Builder
  public abstract static class Builder {
    public abstract Builder setPackageInfos(Set<AttestationPackageInfo> value);

    abstract ImmutableSet.Builder<AttestationPackageInfo> packageInfosBuilder();

    @CanIgnoreReturnValue
    public final Builder addPackageInfo(AttestationPackageInfo value) {
      packageInfosBuilder().add(value);
      return this;
    }

    public abstract Builder setSignatureDigests(Set<ByteString> value);

    abstract ImmutableSet.Builder<ByteString> signatureDigestsBuilder();

    @CanIgnoreReturnValue
    public final Builder addSignatureDigest(ByteString value) {
      signatureDigestsBuilder().add(value);
      return this;
    }

    @CanIgnoreReturnValue
    public final Builder addSignatureDigest(byte[] value) {
      return addSignatureDigest(ByteString.copyFrom(value));
    }

    public abstract AttestationApplicationId build();
  }

  static AttestationApplicationId createAttestationApplicationId(byte[] attestationApplicationId) {
    return createAttestationApplicationId(attestationApplicationId, "attestation application id");
  }

  static AttestationApplicationId createAttestationApplicationId(
      byte[] attestationApplicationId, String location) {
    AttestationApplicationId.Builder builder = AttestationApplicationId.builder();
    final ASN1Sequence attestationApplicationIdSequence;
    try {
      attestationApplicationIdSequence = ASN1Sequence.getInstance(attestationApplicationId);
    } catch (RuntimeException e) {
      throw new IllegalArgumentException(
          String.format("Malformed %s: %s", location, e.getMessage()), e);
    }
    if (attestationApplicationIdSequence == null) {
      // Preserve the historical NullPointerException contract for callers.
      throw new NullPointerException("attestationApplicationId");
    }
    try {
      ASN1Encodable packageInfosElement =
          attestationApplicationIdSequence.getObjectAt(
              ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX);
      if (!(packageInfosElement instanceof ASN1Set)) {
        throw new IllegalArgumentException(
            String.format(
                "Expected ASN.1 SET of package infos at %s[%d]; found %s instead.",
                location,
                ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX,
                packageInfosElement.getClass().getName()));
      }
      ASN1Set attestationPackageInfos = (ASN1Set) packageInfosElement;
      for (int i = 0; i < attestationPackageInfos.size(); i++) {
        builder.addPackageInfo(
            AttestationPackageInfo.create(
                attestationPackageInfos.getObjectAt(i),
                String.format("%s.packageInfos[%d]", location, i)));
      }

      ASN1Encodable digestsElement =
          attestationApplicationIdSequence.getObjectAt(
              ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX);
      if (!(digestsElement instanceof ASN1Set)) {
        throw new IllegalArgumentException(
            String.format(
                "Expected ASN.1 SET of signature digests at %s[%d]; found %s instead.",
                location,
                ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX,
                digestsElement.getClass().getName()));
      }
      ASN1Set digests = (ASN1Set) digestsElement;
      for (int i = 0; i < digests.size(); i++) {
        ASN1Encodable digestElement = digests.getObjectAt(i);
        if (!(digestElement instanceof ASN1OctetString)) {
          throw new IllegalArgumentException(
              String.format(
                  "Expected ASN.1 OCTET STRING signature digest at %s.signatureDigests[%d];"
                      + " found %s instead.",
                  location, i, digestElement.getClass().getName()));
        }
        builder.addSignatureDigest(((ASN1OctetString) digestElement).getOctets());
      }
      return builder.build();
    } catch (IllegalArgumentException e) {
      throw e;
    } catch (RuntimeException e) {
      throw new IllegalArgumentException(
          String.format("Malformed %s: %s", location, e.getMessage()), e);
    }
  }

  byte[] getEncoded() {
    ASN1Encodable[] applicationIdAsn1Array = new ASN1Encodable[2];
    applicationIdAsn1Array[ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX] =
        new DERSet(
            packageInfos().stream()
                .map(AttestationPackageInfo::toAsn1Sequence)
                .toArray(ASN1Sequence[]::new));
    applicationIdAsn1Array[ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX] =
        new DERSet(
            signatureDigests().stream()
                .map(ByteString::toByteArray)
                .map(DEROctetString::new)
                .toArray(DEROctetString[]::new));

    try {
      return new DERSequence(applicationIdAsn1Array).getEncoded();
    } catch (IOException e) {
      throw new IllegalArgumentException(e);
    }
  }

  /** Provides package's name and version number. */
  @AutoValue
  @Immutable
  public abstract static class AttestationPackageInfo {
    public abstract String packageName();

    public abstract long version();

    public static Builder builder() {
      return new AutoValue_AttestationApplicationId_AttestationPackageInfo.Builder();
    }

    /** Builder for {@link AttestationPackageInfo}. */
    @AutoValue.Builder
    public abstract static class Builder {
      public abstract Builder setPackageName(String packageName);

      public abstract Builder setVersion(long version);

      public abstract AttestationPackageInfo build();
    }

    private static AttestationPackageInfo create(ASN1Encodable packageInfo, String location) {
      if (!(packageInfo instanceof ASN1Sequence)) {
        throw new IllegalArgumentException(
            String.format(
                "Expected ASN.1 SEQUENCE package info at %s; found %s instead.",
                location, packageInfo.getClass().getName()));
      }
      ASN1Sequence packageInfoSequence = (ASN1Sequence) packageInfo;
      ASN1Encodable packageNameElement =
          packageInfoSequence.getObjectAt(ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX);
      if (!(packageNameElement instanceof ASN1OctetString)) {
        throw new IllegalArgumentException(
            String.format(
                "Expected ASN.1 OCTET STRING package name at %s[%d]; found %s instead.",
                location,
                ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX,
                packageNameElement.getClass().getName()));
      }
      String packageName =
          new String(((ASN1OctetString) packageNameElement).getOctets(), UTF_8);
      long version =
          ASN1Parsing.getLongFromAsn1(
              packageInfoSequence.getObjectAt(ATTESTATION_PACKAGE_INFO_VERSION_INDEX),
              String.format("%s[%d]", location, ATTESTATION_PACKAGE_INFO_VERSION_INDEX));
      return AttestationPackageInfo.builder()
          .setPackageName(packageName)
          .setVersion(version)
          .build();
    }

    ASN1Sequence toAsn1Sequence() {
      ASN1Encodable[] packageInfoAsn1Array = new ASN1Encodable[2];
      packageInfoAsn1Array[ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX] =
          new DEROctetString(packageName().getBytes(UTF_8));
      packageInfoAsn1Array[ATTESTATION_PACKAGE_INFO_VERSION_INDEX] = new ASN1Integer(version());
      return new DERSequence(packageInfoAsn1Array);
    }
  }
}
