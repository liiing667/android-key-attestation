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

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.google.gson.stream.JsonReader;
import java.io.FilterReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Objects;
import java.util.regex.Pattern;
import okhttp3.Cache;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * Utils for fetching and decoding attestation certificate status.
 *
 * <p>The status list maps certificate serial numbers to their revocation status. Serial numbers
 * may be encoded as decimal or hexadecimal strings; both forms are canonicalized to a unique
 * certificate identifier (lowercase hexadecimal, no leading zeros) so that every certificate
 * appears at most once in the parsed document.
 *
 * <p>Parsing is defensive:
 *
 * <ul>
 *   <li>The document is parsed as a stream with a hard limit on its size and entry count.
 *   <li>Entry keys must be valid serial numbers; anything else (including URIs) is rejected.
 *   <li>Duplicate or conflicting records for the same certificate are merged with a stable,
 *       order-independent policy: any conflict is resolved conservatively as {@link Status#REVOKED}
 *       with {@link Reason#UNSPECIFIED}.
 * </ul>
 */
public class CertificateRevocationStatus {

  private static final String STATUS_URL = "https://android.googleapis.com/attestation/status";
  private static final String CACHE_PATH = "httpcache";
  private static final Cache CACHE = new Cache(new File(CACHE_PATH), 10 * 1024 * 1024);
  private static final OkHttpClient CLIENT = new OkHttpClient.Builder()
          .cache(CACHE)
          .build();

  /** Maximum number of characters read from a status list document. */
  static final long MAX_STATUS_LIST_CHARS = 16 * 1024 * 1024;

  /** Maximum number of entries accepted in a status list document. */
  static final long MAX_ENTRIES = 500_000;

  /** Maximum length of a serial number key, in characters. */
  static final int MAX_SERIAL_NUMBER_LENGTH = 128;

  private static final Pattern DECIMAL_SERIAL = Pattern.compile("[0-9]+");
  private static final Pattern HEX_SERIAL = Pattern.compile("[0-9a-fA-F]+");

  public final Status status;
  public final Reason reason;
  public final String comment;
  public final String expires;

  /**
   * Fetches the status list and returns it as a map from canonical serial number (lowercase
   * hexadecimal, no leading zeros) to revocation status.
   */
  public static HashMap<String, CertificateRevocationStatus> fetchAllEntries() throws IOException {
    URL url = new URL(STATUS_URL);
    return loadAllEntries(new InputStreamReader(url.openStream(), UTF_8));
  }

  /**
   * Loads the status list from a file and returns it as a map from canonical serial number
   * (lowercase hexadecimal, no leading zeros) to revocation status.
   */
  public static HashMap<String, CertificateRevocationStatus> loadAllEntriesFromFile(String filePath)
      throws IOException {
    try (Reader reader = Files.newBufferedReader(Path.of(filePath))) {
      return loadAllEntries(reader);
    }
  }

  static HashMap<String, CertificateRevocationStatus> loadAllEntries(Reader statusListReader)
      throws IOException {
    HashMap<String, StatusAccumulator> canonicalToAccumulator = new HashMap<>();
    readEntries(
        statusListReader,
        (canonicalSerial, record) ->
            canonicalToAccumulator
                .computeIfAbsent(canonicalSerial, unused -> new StatusAccumulator())
                .add(record));

    HashMap<String, CertificateRevocationStatus> serialNumberToStatus = new HashMap<>();
    canonicalToAccumulator.forEach(
        (canonicalSerial, accumulator) -> {
          CertificateRevocationStatus merged = accumulator.merged();
          if (merged != null) {
            serialNumberToStatus.put(canonicalSerial, merged);
          }
        });
    return serialNumberToStatus;
  }

  public static CertificateRevocationStatus loadStatusFromFile(BigInteger serialNumber,
      String filePath)
      throws IOException {
    try (Reader reader = Files.newBufferedReader(Path.of(filePath))) {
      return decodeStatus(canonicalSerialNumber(serialNumber), reader);
    }
  }

  public static CertificateRevocationStatus loadStatusFromFile(String serialNumber, String filePath)
      throws IOException {
    try (Reader reader = Files.newBufferedReader(Path.of(filePath))) {
      return decodeStatus(canonicalSerialNumber(serialNumber), reader);
    }
  }

  static CertificateRevocationStatus loadStatus(String serialNumber, Reader statusListReader)
      throws IOException {
    return decodeStatus(canonicalSerialNumber(serialNumber), statusListReader);
  }

  public static CertificateRevocationStatus fetchStatus(BigInteger serialNumber)
      throws IOException {
    return fetchStatusByCanonicalSerial(canonicalSerialNumber(serialNumber));
  }

  public static CertificateRevocationStatus fetchStatus(String serialNumber) throws IOException {
    return fetchStatusByCanonicalSerial(canonicalSerialNumber(serialNumber));
  }

  private static CertificateRevocationStatus fetchStatusByCanonicalSerial(String canonicalSerial)
      throws IOException {
    URL url;
    try {
      url = new URL(STATUS_URL);
    } catch (MalformedURLException e) {
      throw new IllegalStateException(e);
    }

    Request request = new Request.Builder()
            .url(url)
            .build();

    try (Response response = CLIENT.newCall(request).execute()) {
      return decodeStatus(canonicalSerial, response.body().charStream());
    }
  }

  private static CertificateRevocationStatus decodeStatus(
      String canonicalSerial, Reader statusListReader) throws IOException {
    StatusAccumulator accumulator = new StatusAccumulator();
    readEntries(
        statusListReader,
        (entrySerial, record) -> {
          if (entrySerial.equals(canonicalSerial)) {
            accumulator.add(record);
          }
        });
    return accumulator.merged();
  }

  /**
   * Streams the entries of a status list document, invoking {@code consumer} once per record with
   * the canonical serial number and the parsed record ({@code null} for records that explicitly
   * mark the certificate as valid).
   */
  private static void readEntries(Reader statusListReader, EntryConsumer consumer)
      throws IOException {
    try (JsonReader reader =
        new JsonReader(new BoundedReader(statusListReader, MAX_STATUS_LIST_CHARS))) {
      reader.beginObject();
      boolean foundEntries = false;
      while (reader.hasNext()) {
        String name = reader.nextName();
        if (!name.equals("entries")) {
          reader.skipValue();
          continue;
        }
        foundEntries = true;
        reader.beginObject();
        long entryCount = 0;
        while (reader.hasNext()) {
          if (++entryCount > MAX_ENTRIES) {
            throw new IOException(
                "Status list contains too many entries (limit: " + MAX_ENTRIES + ")");
          }
          String rawSerial = reader.nextName();
          String canonicalSerial = canonicalSerialNumber(rawSerial);
          consumer.accept(canonicalSerial, parseRecord(JsonParser.parseReader(reader), rawSerial));
        }
        reader.endObject();
      }
      reader.endObject();
      if (!foundEntries) {
        throw new IOException("Status list does not contain an \"entries\" object");
      }
    } catch (JsonSyntaxException | IllegalStateException e) {
      throw new IOException("Invalid attestation status list", e);
    }
  }

  /**
   * Parses a single status record. Returns {@code null} if the record explicitly marks the
   * certificate as valid.
   */
  private static CertificateRevocationStatus parseRecord(JsonElement element, String serialNumber)
      throws IOException {
    if (!element.isJsonObject()) {
      throw new IOException("Status entry for serial " + serialNumber + " is not a JSON object");
    }
    JsonObject record = element.getAsJsonObject();
    String status = getOptionalString(record, "status", serialNumber);
    if (status == null) {
      throw new IOException("Status entry for serial " + serialNumber + " has no \"status\" field");
    }
    if (status.equals("VALID")) {
      return null;
    }
    Status parsedStatus;
    try {
      parsedStatus = Status.valueOf(status);
    } catch (IllegalArgumentException e) {
      throw new IOException(
          "Status entry for serial " + serialNumber + " has unknown status \"" + status + "\"", e);
    }

    Reason reason = Reason.UNSPECIFIED;
    String reasonString = getOptionalString(record, "reason", serialNumber);
    if (reasonString != null) {
      try {
        reason = Reason.valueOf(reasonString);
      } catch (IllegalArgumentException e) {
        throw new IOException(
            "Status entry for serial "
                + serialNumber
                + " has unknown reason \""
                + reasonString
                + "\"",
            e);
      }
    }

    return new CertificateRevocationStatus(
        parsedStatus,
        reason,
        getOptionalString(record, "comment", serialNumber),
        getOptionalString(record, "expires", serialNumber));
  }

  private static String getOptionalString(JsonObject record, String field, String serialNumber)
      throws IOException {
    JsonElement value = record.get(field);
    if (value == null || value.isJsonNull()) {
      return null;
    }
    if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
      throw new IOException(
          "Status entry for serial "
              + serialNumber
              + " has a non-string \""
              + field
              + "\" field");
    }
    return value.getAsString();
  }

  /**
   * Returns the canonical form of a serial number: lowercase hexadecimal with no leading zeros.
   * Serial numbers consisting only of decimal digits are interpreted as decimal; serial numbers
   * containing hexadecimal letters are interpreted as hexadecimal. Anything else is rejected.
   */
  private static String canonicalSerialNumber(String serialNumber) throws IOException {
    if (serialNumber == null) {
      throw new IllegalArgumentException("serialNumber cannot be null");
    }
    if (serialNumber.isEmpty() || serialNumber.length() > MAX_SERIAL_NUMBER_LENGTH) {
      throw new IOException("Invalid certificate serial number in status list: " + serialNumber);
    }
    if (DECIMAL_SERIAL.matcher(serialNumber).matches()) {
      return new BigInteger(serialNumber, 10).toString(16);
    }
    if (HEX_SERIAL.matcher(serialNumber).matches()) {
      return new BigInteger(serialNumber, 16).toString(16);
    }
    throw new IOException("Invalid certificate serial number in status list: " + serialNumber);
  }

  private static String canonicalSerialNumber(BigInteger serialNumber) {
    return Objects.requireNonNull(serialNumber, "serialNumber cannot be null").toString(16);
  }

  private interface EntryConsumer {
    void accept(String canonicalSerial, CertificateRevocationStatus record) throws IOException;
  }

  /**
   * Merges all records seen for a single certificate into one status using a stable,
   * order-independent policy: identical records collapse to one, and any conflict (including a
   * "valid" record alongside a revocation record) is resolved conservatively as untrusted.
   */
  private static final class StatusAccumulator {
    private CertificateRevocationStatus untrusted;
    private boolean sawValid;
    private boolean conflict;

    void add(CertificateRevocationStatus record) {
      if (record == null) {
        if (untrusted != null) {
          conflict = true;
        }
        sawValid = true;
        return;
      }
      if (sawValid) {
        conflict = true;
      }
      if (untrusted == null) {
        untrusted = record;
      } else if (!untrusted.hasSameContentAs(record)) {
        conflict = true;
      }
    }

    CertificateRevocationStatus merged() {
      if (conflict) {
        return conflicting();
      }
      return untrusted;
    }
  }

  private static CertificateRevocationStatus conflicting() {
    return new CertificateRevocationStatus(
        Status.REVOKED, Reason.UNSPECIFIED, "Conflicting entries in status list", null);
  }

  private boolean hasSameContentAs(CertificateRevocationStatus other) {
    return status == other.status
        && reason == other.reason
        && Objects.equals(comment, other.comment)
        && Objects.equals(expires, other.expires);
  }

  /** A reader that throws an {@link IOException} once more than {@code maxChars} are read. */
  private static final class BoundedReader extends FilterReader {
    private final long maxChars;
    private long charsRead;

    BoundedReader(Reader in, long maxChars) {
      super(in);
      this.maxChars = maxChars;
    }

    @Override
    public int read() throws IOException {
      int c = super.read();
      if (c != -1) {
        account(1);
      }
      return c;
    }

    @Override
    public int read(char[] cbuf, int off, int len) throws IOException {
      int n = super.read(cbuf, off, len);
      if (n > 0) {
        account(n);
      }
      return n;
    }

    @Override
    public long skip(long n) throws IOException {
      long skipped = super.skip(n);
      account(skipped);
      return skipped;
    }

    private void account(long n) throws IOException {
      charsRead += n;
      if (charsRead > maxChars) {
        throw new IOException(
            "Status list exceeds the maximum supported size of " + maxChars + " characters");
      }
    }
  }

  public enum Status {
    REVOKED, SUSPENDED
  }

  public enum Reason {
    UNSPECIFIED, KEY_COMPROMISE, CA_COMPROMISE, SUPERSEDED, SOFTWARE_FLAW
  }

  public CertificateRevocationStatus() {
    status = Status.REVOKED;
    reason = Reason.UNSPECIFIED;
    comment = null;
    expires = null;
  }

  private CertificateRevocationStatus(
      Status status, Reason reason, String comment, String expires) {
    this.status = status;
    this.reason = reason;
    this.comment = comment;
    this.expires = expires;
  }
}
