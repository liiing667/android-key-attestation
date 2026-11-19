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

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;

/** Utils to get java representation of ASN1 types. */
class ASN1Parsing {

  private ASN1Parsing() {}

  static boolean getBooleanFromAsn1(ASN1Encodable asn1Value) {
    if (asn1Value instanceof ASN1Boolean) {
      return ((ASN1Boolean) asn1Value).isTrue();
    } else {
      throw new IllegalArgumentException(
          "Boolean value expected; found " + className(asn1Value) + " instead.");
    }
  }

  static int getIntegerFromAsn1(ASN1Encodable asn1Value) {
    try {
      if (asn1Value instanceof ASN1Integer) {
        return ((ASN1Integer) asn1Value).getValue().intValueExact();
      } else if (asn1Value instanceof ASN1Enumerated) {
        return ((ASN1Enumerated) asn1Value).getValue().intValueExact();
      }
    } catch (ArithmeticException e) {
      throw new IllegalArgumentException("Integer value out of 32-bit range.", e);
    }
    throw new IllegalArgumentException(
        "Integer value expected; found " + className(asn1Value) + " instead.");
  }

  static long getLongFromAsn1(ASN1Encodable asn1Value) {
    try {
      if (asn1Value instanceof ASN1Integer) {
        return ((ASN1Integer) asn1Value).getValue().longValueExact();
      } else if (asn1Value instanceof ASN1Enumerated) {
        return ((ASN1Enumerated) asn1Value).getValue().longValueExact();
      }
    } catch (ArithmeticException e) {
      throw new IllegalArgumentException("Integer value out of 64-bit range.", e);
    }
    throw new IllegalArgumentException(
        "Integer value expected; found " + className(asn1Value) + " instead.");
  }

  static ASN1OctetString getOctetStringFromAsn1(ASN1Encodable asn1Value) {
    if (asn1Value instanceof ASN1OctetString) {
      return (ASN1OctetString) asn1Value;
    }
    throw new IllegalArgumentException(
        "Octet string value expected; found " + className(asn1Value) + " instead.");
  }

  static ASN1Sequence getSequenceFromAsn1(ASN1Encodable asn1Value) {
    if (asn1Value instanceof ASN1Sequence) {
      return (ASN1Sequence) asn1Value;
    }
    throw new IllegalArgumentException(
        "Sequence value expected; found " + className(asn1Value) + " instead.");
  }

  static ASN1Set getSetFromAsn1(ASN1Encodable asn1Value) {
    if (asn1Value instanceof ASN1Set) {
      return (ASN1Set) asn1Value;
    }
    throw new IllegalArgumentException(
        "Set value expected; found " + className(asn1Value) + " instead.");
  }

  static ASN1TaggedObject getTaggedObjectFromAsn1(ASN1Encodable asn1Value) {
    if (asn1Value instanceof ASN1TaggedObject) {
      return (ASN1TaggedObject) asn1Value;
    }
    throw new IllegalArgumentException(
        "Tagged object expected; found " + className(asn1Value) + " instead.");
  }

  private static String className(ASN1Encodable asn1Value) {
    return asn1Value == null ? "null" : asn1Value.getClass().getName();
  }
}
