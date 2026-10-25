import 'dart:convert';
import 'dart:typed_data';

import 'package:base32/base32.dart';
import 'package:collection/collection.dart';
import 'package:cryptography/cryptography.dart' hide PublicKey;
import 'package:dart_pg/dart_pg.dart'
    show
        BaseKey,
        PacketList,
        PacketReader,
        PacketType,
        PublicKey,
        PublicKeyPacket;

typedef HkpKeyServer = ({
  String host,
  String displayName,
  bool useV2,
  bool keyIdentitiesVerifies,
});
typedef UserIdKeyFetchKey = ({
  Uint8List bytes,
  Uint8List? fingerprint,
  bool isValid,
  bool isExpired,
  bool isRevoked,
  bool isUnreadable,
});
typedef UserIdKeyFetchResult = ({
  List<UserIdKeyFetchKey> keys,
  UserIdKeyFetchOrigin? origin,
  String? originHost,
});

final _emailShapeRegex = RegExp(r"^[^\s@]+@[^\s@]+$");

bool _looksLikeEmail(String value) => _emailShapeRegex.hasMatch(value);

class UserId {
  final String? name;
  final String? comment;
  final String email;

  UserId({this.name, this.comment, required this.email});

  factory UserId.parse(String userIdString) {
    final regex = RegExp(
      r"^\s*(?:([^<(\s](?:[^<(]*[^<(\s])?)\s*)?(?:\(([^)]*)\)\s*)?<(.+)>$",
    );
    var match = regex.firstMatch(userIdString);
    if (match == null) {
      final retryMatch = regex.firstMatch("<$userIdString>");
      final retryEmail = retryMatch?.group(3);
      if (retryEmail != null && _looksLikeEmail(retryEmail)) match = retryMatch;
    }
    if (match == null) {
      throw ArgumentError.value(
        userIdString,
        "userIdString",
        "Invalid user ID format",
      );
    }
    final name = match.group(1);
    final comment = match.group(2);
    final email = match.group(3)!;
    if (email.isEmpty) {
      throw ArgumentError.value(
        userIdString,
        "userIdString",
        "Email cannot be empty",
      );
    }
    return UserId(name: name, comment: comment, email: email);
  }

  static UserId? tryParse(String userIdString) {
    try {
      return UserId.parse(userIdString);
    } catch (_) {
      return null;
    }
  }

  UserId copyWith({
    ValuePresence<String?> name = const ValuePresence.absent(),
    ValuePresence<String?> comment = const ValuePresence.absent(),
    String? email,
  }) => UserId(
    name: name | this.name,
    comment: comment | this.comment,
    email: email ?? this.email,
  );

  @override
  String toString() {
    final namePart = name ?? "";
    final commentPart = comment != null ? " ($comment)" : "";
    return "$namePart$commentPart <$email>".trim();
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is UserId &&
          runtimeType == other.runtimeType &&
          name == other.name &&
          comment == other.comment &&
          email == other.email;
  @override
  int get hashCode => Object.hash(name, comment, email);

  bool isEmailEquivalent(UserId other) =>
      email.trim().toLowerCase() == other.email.trim().toLowerCase();

  static const List<HkpKeyServer> defaultHkpKeyServers = [
    (
      host: "keys.openpgp.org",
      displayName: "OpenPGP",
      useV2: false,
      keyIdentitiesVerifies: true,
    ),
    (
      host: "keys.mailvelope.com",
      displayName: "Mailvelope",
      useV2: false,
      keyIdentitiesVerifies: true,
    ),
    (
      host: "keyserver.ubuntu.com",
      displayName: "Ubuntu",
      useV2: false,
      keyIdentitiesVerifies: false,
    ),
  ];

  static const List<HkpKeyServer> commonHkpKeyServers = [
    ...defaultHkpKeyServers,
    (
      host: "api.protonmail.ch",
      displayName: "Proton",
      useV2: false,
      keyIdentitiesVerifies: true,
    ),
    (
      host: "pgp.mit.edu",
      displayName: "MIT",
      useV2: false,
      keyIdentitiesVerifies: false,
    ),
    (
      host: "pgp.surfnet.nl",
      displayName: "SURFnet",
      useV2: false,
      keyIdentitiesVerifies: false,
    ),
    (
      host: "pgp.circl.lu",
      displayName: "CIRCL",
      useV2: false,
      keyIdentitiesVerifies: false,
    ),
    (
      host: "pgpkeys.eu",
      displayName: "PGPKeys.eu",
      useV2: false,
      keyIdentitiesVerifies: false,
    ),
    (
      host: "keyserver.dobrev.eu",
      displayName: "Dobrev",
      useV2: false,
      keyIdentitiesVerifies: false,
    ),
  ];

  static const Duration defaultRequestTimeout = Duration(seconds: 10);

  Future<UserIdKeyFetchResult?> fetchKeyFromPublic(
    HttpClientProvider client, {
    List<Uint8List>? fingerprints,
    List<HkpKeyServer> hkpKeyServers = defaultHkpKeyServers,
    Duration timeout = defaultRequestTimeout,
  }) async {
    final results = await fetchKeyFromPublicFull(
      client,
      fingerprints: fingerprints,
      hkpKeyServers: hkpKeyServers,
      returnAfterFirst: true,
      timeout: timeout,
    );
    for (final result in results) {
      final validKeys = result.keys.where((k) => k.isValid).toList();
      if (validKeys.isNotEmpty) {
        return (
          keys: validKeys,
          origin: result.origin,
          originHost: result.originHost,
        );
      }
    }
    return null;
  }

  Future<List<UserIdKeyFetchResult>> fetchKeyFromPublicFull(
    HttpClientProvider client, {
    List<Uint8List>? fingerprints,
    List<HkpKeyServer> hkpKeyServers = defaultHkpKeyServers,
    bool returnAfterFirst = false,
    Duration timeout = defaultRequestTimeout,
  }) async {
    final results = <UserIdKeyFetchResult>[];

    Future<HttpResponse> send(HttpRequest request) =>
        client.send(request).timeout(timeout);

    final emailParts = email.split("@");
    if (emailParts.length != 2) {
      throw ArgumentError.value(email, "email", "Invalid email format");
    }
    final localPart = emailParts[0];
    final domainPart = emailParts[1];

    final localHash = await Sha1().hash(utf8.encode(localPart.toLowerCase()));
    final localFormatted = base32.encode(
      Uint8List.fromList(localHash.bytes),
      encoding: .zbase32,
    );

    List<Uint8List> splitIntoKeySegments(Uint8List raw) {
      final starts = <int>[];
      var offset = 0;
      try {
        while (offset < raw.length) {
          final start = offset;
          final reader = PacketReader.read(raw, offset);
          if (reader.type == PacketType.publicKey) starts.add(start);
          offset = reader.offset;
        }
      } catch (_) {}
      if (starts.isEmpty) return [];
      return [
        for (var i = 0; i < starts.length; i++)
          raw.sublist(
            starts[i],
            i + 1 < starts.length ? starts[i + 1] : raw.length,
          ),
      ];
    }

    Uint8List? tryReadFingerprint(Uint8List segment) {
      try {
        final reader = PacketReader.read(segment, 0);
        if (reader.type != PacketType.publicKey) return null;
        return PublicKeyPacket.fromBytes(reader.data).fingerprint;
      } catch (_) {
        return null;
      }
    }

    List<UserIdKeyFetchKey> evaluateKeySegments(List<Uint8List> segments) {
      final result = <UserIdKeyFetchKey>[];
      for (final segment in segments) {
        final PublicKey key;
        try {
          key = PublicKey(PacketList.decode(segment));
        } catch (_) {
          result.add((
            bytes: segment,
            fingerprint: tryReadFingerprint(segment),
            isValid: false,
            isExpired: false,
            isRevoked: false,
            isUnreadable: true,
          ));
          continue;
        }

        var isRevoked = false;
        try {
          isRevoked = key.isRevoked();
        } catch (_) {
          isRevoked = false;
        }

        DateTime? primaryExpiration;
        try {
          primaryExpiration = key.expirationTime;
          if (primaryExpiration == null) {
            for (final user in key.users) {
              try {
                if (user.isRevoked()) continue;
              } catch (_) {
                continue;
              }
              final userExpiration = BaseKey.keyExpiration(
                user.selfSignatures.toList(),
              );
              if (userExpiration != null) {
                primaryExpiration = userExpiration;
                break;
              }
            }
          }
        } catch (_) {
          primaryExpiration = null;
        }

        var encryptionSubkeysExpired = false;
        try {
          final encryptionSubkeys = key.subkeys.where((subkey) {
            try {
              return subkey.isEncryptionKey;
            } catch (_) {
              return false;
            }
          });
          if (encryptionSubkeys.isNotEmpty) {
            encryptionSubkeysExpired = !encryptionSubkeys.any((subkey) {
              try {
                if (subkey.isRevoked()) return false;
                final expiration = subkey.expirationTime;
                return expiration == null || expiration.isAfter(DateTime.now());
              } catch (_) {
                return false;
              }
            });
          }
        } catch (_) {
          encryptionSubkeysExpired = false;
        }

        final isExpired =
            (primaryExpiration != null &&
                primaryExpiration.isBefore(DateTime.now())) ||
            encryptionSubkeysExpired;

        var matchesFingerprint = true;
        if (fingerprints != null) {
          try {
            matchesFingerprint = fingerprints.any(
              (f) => const ListEquality<int>().equals(f, key.fingerprint),
            );
          } catch (_) {
            matchesFingerprint = false;
          }
        }

        var matchesEmail = true;
        var hasUnreadableUserId = false;
        try {
          final nonRevokedUsers = key.users.where((user) {
            try {
              return !user.isRevoked();
            } catch (_) {
              return false;
            }
          });
          matchesEmail = false;
          var anyUserIdParsed = false;
          for (final user in nonRevokedUsers) {
            final parsed = UserId.tryParse(user.userID);
            if (parsed == null) continue;
            anyUserIdParsed = true;
            if (parsed.isEmailEquivalent(this)) {
              matchesEmail = true;
              break;
            }
          }
          if (!anyUserIdParsed && nonRevokedUsers.isNotEmpty) {
            hasUnreadableUserId = true;
          }
        } catch (_) {
          matchesEmail = false;
        }

        final isValid =
            !isRevoked && !isExpired && matchesFingerprint && matchesEmail;

        result.add((
          bytes: segment,
          fingerprint: key.fingerprint,
          isValid: isValid,
          isExpired: isExpired,
          isRevoked: isRevoked,
          isUnreadable: hasUnreadableUserId,
        ));
      }
      return result;
    }

    List<UserIdKeyFetchKey> formatWkdResponse(HttpResponse response) =>
        evaluateKeySegments(splitIntoKeySegments(response.body));

    List<UserIdKeyFetchKey> formatHkpResponse(HttpResponse response) {
      final raw = dearmorPublicKeyBlock(
        utf8.decode(response.body, allowMalformed: true),
      );
      if (raw == null) return [];
      return evaluateKeySegments(splitIntoKeySegments(raw));
    }

    final advancedUrl = Uri.tryParse(
      "https://openpgpkey.$domainPart/.well-known/openpgpkey/${domainPart.toLowerCase()}/hu/$localFormatted",
    )?.replace(queryParameters: {"l": localPart});
    final directUrl = Uri.tryParse(
      "https://$domainPart/.well-known/openpgpkey/hu/$localFormatted",
    )?.replace(queryParameters: {"l": localPart});
    for (var url in [
      if (advancedUrl != null)
        (advancedUrl, UserIdKeyFetchOrigin.webKeyDirectoryAdvanced),
      if (directUrl != null)
        (directUrl, UserIdKeyFetchOrigin.webKeyDirectoryDirect),
    ]) {
      final HttpResponse response;
      try {
        response = await send(
          HttpRequest(
            method: "GET",
            url: url.$1,
            headers: {"Accept": "application/octet-stream"},
            body: Uint8List(0),
          ),
        );
      } catch (_) {
        continue;
      }
      if (response.statusCode != 200) continue;

      final formatted = formatWkdResponse(response);
      if (formatted.isEmpty) continue;
      results.add((keys: formatted, origin: url.$2, originHost: url.$1.host));
      if (returnAfterFirst && formatted.any((k) => k.isValid)) return results;
    }

    final fingerprintHex = fingerprints?.length == 1
        ? fingerprints!.first
              .map((d) => d.toRadixString(16).padLeft(2, "0"))
              .join()
              .toUpperCase()
        : null;

    for (var hpk in hkpKeyServers) {
      final host = hpk.host.replaceFirst(RegExp(r"/$"), "");
      final Uri? url;
      if (hpk.useV2) {
        final lookup = fingerprintHex != null
            ? "by-fingerprint/$fingerprintHex"
            : "by-identity/${Uri.encodeComponent(email)}";
        url = Uri.tryParse("https://$host/pks/v2/certs/$lookup");
      } else {
        url = Uri.tryParse("https://$host/pks/lookup")?.replace(
          queryParameters: {
            "op": "get",
            "search": fingerprintHex != null ? "0x$fingerprintHex" : email,
          },
        );
      }
      if (url == null) continue;
      try {
        final response = await send(
          HttpRequest(
            method: "GET",
            url: url,
            headers: {if (hpk.useV2) "Accept": "application/pgp-keys"},
            body: Uint8List(0),
          ),
        );
        if (response.statusCode == 200) {
          final formatted = hpk.useV2
              ? formatWkdResponse(response)
              : formatHkpResponse(response);
          if (formatted.isEmpty) continue;
          results.add((
            keys: formatted,
            origin: UserIdKeyFetchOrigin.hkpKeyServer,
            originHost: "$host|${hpk.displayName}|${hpk.keyIdentitiesVerifies}",
          ));
          if (returnAfterFirst && formatted.any((k) => k.isValid)) {
            return results;
          }
        }
      } catch (_) {
        continue;
      }
    }

    return results;
  }
}

Uint8List? dearmorPublicKeyBlock(String armored) {
  final dataLines = <String>[];
  var seenBegin = false;
  var inBody = false;
  for (final rawLine in armored.split("\n")) {
    final line = rawLine.trim();
    if (line.contains("-----BEGIN PGP PUBLIC KEY BLOCK")) {
      seenBegin = true;
      inBody = false;
      continue;
    }
    if (!seenBegin) continue;
    if (line.contains("-----END PGP PUBLIC KEY BLOCK")) {
      seenBegin = false;
      continue;
    }
    if (!inBody) {
      if (line.isEmpty) inBody = true;
      continue;
    }
    if (line.isEmpty || line.startsWith("=")) continue;
    dataLines.add(line);
  }
  if (dataLines.isEmpty) return null;
  try {
    return base64.decode(dataLines.join());
  } catch (_) {
    return null;
  }
}

enum UserIdKeyFetchOrigin {
  webKeyDirectoryAdvanced("Web Key Directory (Advanced)"),
  webKeyDirectoryDirect("Web Key Directory (Direct)"),
  hkpKeyServer("HKP Key Server");

  final String displayName;
  const UserIdKeyFetchOrigin(this.displayName);
}

final class ValuePresence<T extends Object?> {
  final bool isPresent;
  final T? value;

  const new present(this.value) : isPresent = true;
  const new absent() : isPresent = false, value = null;

  T orElse(T Function() defaultValue) => isPresent ? value! : defaultValue();
  T or(T defaultValue) => isPresent ? value! : defaultValue;

  T operator |(T defaultValue) => or(defaultValue);
}

class HttpRequest {
  final String method;
  final Uri url;
  final Map<String, String> headers;
  final Uint8List body;

  HttpRequest({
    required this.method,
    required this.url,
    required this.headers,
    required this.body,
  });

  HttpRequest copyWith({
    String? method,
    Uri? url,
    Map<String, String>? headers,
    Uint8List? body,
  }) => HttpRequest(
    method: method ?? this.method,
    url: url ?? this.url,
    headers: headers ?? this.headers,
    body: body ?? this.body,
  );
}

class HttpResponse {
  final int statusCode;
  final Map<String, String> headers;
  final Uint8List body;

  HttpResponse({
    required this.statusCode,
    required this.headers,
    required this.body,
  });

  HttpResponse copyWith({
    int? statusCode,
    Map<String, String>? headers,
    Uint8List? body,
  }) => HttpResponse(
    statusCode: statusCode ?? this.statusCode,
    headers: headers ?? this.headers,
    body: body ?? this.body,
  );
}

/// A primitive http client interface for sending HTTP requests and receiving
/// responses.
///
/// The implementer is responsible for providing the logic to send HTTP requests
/// and returning the corresponding HTTP responses.
///
/// The implementer MUST enforce correct HTTPS usage for all requests and MUST
/// verify that no 301, 302, or other redirect has taken place.
abstract class HttpClientProvider {
  Future<HttpResponse> send(HttpRequest request);
}

void main(List<String> args) async {
  final userId1 = UserId.parse("John Doe (Developer) <john.doe@example.com>");
  print(userId1);

  final userId2 = UserId.tryParse("Jane Doe (Designer) <jane.doe@example.com>");
  print(userId2);

  final userId3 = UserId.tryParse("Invalid User <incomplete.email@tag");
  print(userId3);

  final userId4 = UserId(email: "anonymous@example.com");
  print(userId4);

  final userId5 = UserId.tryParse("<another.user@example.com>");
  print(userId5);
}
