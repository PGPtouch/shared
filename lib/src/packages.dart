import 'dart:typed_data';

import 'package:collection/collection.dart';

import 'byte_package.dart';

final protocolInitializerDefaults = (id: [0x50, 0x54], version: 1);
List<BytePackagePart> protocolInitializer([List<int>? id, int? version]) =>
    List.unmodifiableOf([
      BytePackageRaw(
        2,
        Uint8List.fromList(id ?? protocolInitializerDefaults.id),
      ),
      BytePackageInt(1, version ?? protocolInitializerDefaults.version),
    ]);

final class Capabilities({
  required final bool nfc,
  required final bool bluetooth,
  required final bool uwb,
}) {
  @override
  String toString() =>
      "Capabilities(nfc: $nfc, bluetooth: $bluetooth, uwb: $uwb)";

  Map<int, bool> toMap() => {0: nfc, 1: bluetooth, 2: uwb};
  factory fromMap(Map<int, bool> map) => Capabilities(
    nfc: map[0] ?? false,
    bluetooth: map[1] ?? false,
    uwb: map[2] ?? false,
  );

  int toInt() => BytePackageBitFlags(null, toMap()).toBytes().toInt();

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is Capabilities &&
          runtimeType == other.runtimeType &&
          nfc == other.nfc &&
          bluetooth == other.bluetooth &&
          uwb == other.uwb;
  @override
  int get hashCode => Object.hash(nfc, bluetooth, uwb);
}

final class NfcBootstrap extends BytePackage {
  @override
  String get className => "NfyBootstrap";

  final List<int>? protocolInitializerId;
  final int? protocolInitializerVersion;

  final int random;
  final Uint8List sessionId;
  final Map<int, bool> capabilities;
  final Uint8List nonce;
  final Uint8List publicX25519Key;

  NfcBootstrap({
    required this.random,
    required this.sessionId,
    required this.capabilities,
    required this.nonce,
    required this.publicX25519Key,
  }) : protocolInitializerId = null,
       protocolInitializerVersion = null;

  NfcBootstrap._({
    required this.protocolInitializerId,
    required this.protocolInitializerVersion,
    required this.random,
    required this.sessionId,
    required this.capabilities,
    required this.nonce,
    required this.publicX25519Key,
  });

  @override
  List<BytePackagePart> get parts => [
    ...protocolInitializer(protocolInitializerId, protocolInitializerVersion),
    BytePackageInt(1, random),
    BytePackageRaw(16, sessionId),
    BytePackageBitFlags(12, capabilities),
    BytePackageRaw(32, nonce),
    BytePackageRaw(32, publicX25519Key),
  ];

  @override
  int get length => 96;

  static NfcBootstrap fromBytes(Uint8List bytes) => BytePackage.fromBytes(
    bytes,
    [
      ...protocolInitializer(),
      BytePackageInt(1, 0),
      BytePackageRaw(16, Uint8List(16)),
      BytePackageBitFlags(12, {}),
      BytePackageRaw(32, Uint8List(32)),
      BytePackageRaw(32, Uint8List(32)),
    ],
    (parts) => NfcBootstrap._(
      protocolInitializerId: parts[0] as List<int>?,
      protocolInitializerVersion: parts[1] as int?,
      random: parts[2] as int,
      sessionId: parts[3] as Uint8List,
      capabilities: parts[4] as Map<int, bool>,
      nonce: parts[5] as Uint8List,
      publicX25519Key: parts[6] as Uint8List,
    ),
  );

  /// Checks if the protocol initializer supplied in [fromBytes] matches the
  /// protocol initializer of the current implementation.
  bool initializerMatchesImplementation() =>
      const ListEquality().equals(
        protocolInitializerId,
        protocolInitializerDefaults.id,
      ) &&
      protocolInitializerVersion == protocolInitializerDefaults.version;
}

final class PayloadType {
  final int value;
  final bool isError;
  const PayloadType(this.value) : isError = false;
  const PayloadType._error(this.value) : isError = true;

  static const handshake = PayloadType(0);
  static const keyExchange = PayloadType(1);
  static const signatureExchange = PayloadType(2);

  static final ErrorPayloadType error = ErrorPayloadType._();

  @override
  String toString() => isError
      ? switch (value) {
          1 => "PayloadType.headerIncompatible",
          2 => "PayloadType.pageTimeout",
          3 => "PayloadType.unableToReadContent",
          _ => "PayloadType($value)",
        }
      : switch (value) {
          0 => "PayloadType.handshake",
          1 => "PayloadType.keyExchange",
          2 => "PayloadType.signatureExchange",
          _ => "PayloadType($value)",
        };

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is PayloadType &&
          runtimeType == other.runtimeType &&
          value == other.value;
  @override
  int get hashCode => value.hashCode;
}

final class ErrorPayloadType {
  ErrorPayloadType._();

  final headerIncompatible = PayloadType._error(1);
  final pageTimeout = PayloadType._error(2);
  final unableToReadContent = PayloadType._error(3);
}

sealed class Payload extends BytePackage {
  final Uint8List requestId;
  final int pageIndex;
  final int pages;

  Payload({
    required this.requestId,
    required this.pageIndex,
    required this.pages,
  });

  static Payload fromBytes(Uint8List bytes) {
    final errorCode = bytes[3];
    if (errorCode != 0) return ErrorReportPayload.fromBytes(bytes);
    final payloadType = PayloadType(bytes[7]);
    return switch (payloadType) {
      .handshake => HandshakePayload.fromBytes(bytes),
      .keyExchange => KeyExchangePayload.fromBytes(bytes),
      .signatureExchange => SignatureExchangePayload.fromBytes(bytes),
      _ => throw UnimplementedError(
        "Payload type $payloadType not implemented.",
      ),
    };
  }

  Payload copyWith();
}

List<BytePackagePart> _payloadHeaderParts({
  List<int>? protocolInitializerId,
  int? protocolInitializerVersion,
  int errorCode = 0,
  required Uint8List requestId,
  required PayloadType payloadType,
  required int pageIndex,
  required int pages,
  required int length,
}) => [
  ...protocolInitializer(protocolInitializerId, protocolInitializerVersion),
  BytePackageInt(1, errorCode),
  BytePackageRaw(3, requestId),
  BytePackageInt(1, payloadType.value),
  BytePackageInt(1, pageIndex),
  BytePackageInt(1, pages),
  BytePackageInt(2, length),
];

final class HandshakePayload extends Payload {
  @override
  String get className => "HandshakePayload";

  final List<int>? protocolInitializerId;
  final int? protocolInitializerVersion;

  final Map<int, bool> capabilities;
  final Uint8List nonce;
  final Uint8List publicX25519Key;

  HandshakePayload({
    required super.requestId,
    required this.capabilities,
    required this.nonce,
    required this.publicX25519Key,
  }) : protocolInitializerId = null,
       protocolInitializerVersion = null,
       super(pageIndex: 1, pages: 1);

  HandshakePayload._({
    required this.protocolInitializerId,
    required this.protocolInitializerVersion,
    required super.requestId,
    required this.capabilities,
    required this.nonce,
    required this.publicX25519Key,
  }) : super(pageIndex: 1, pages: 1);

  @override
  List<BytePackagePart> get parts => [
    ..._payloadHeaderParts(
      protocolInitializerId: protocolInitializerId,
      protocolInitializerVersion: protocolInitializerVersion,
      errorCode: 0,
      requestId: requestId,
      payloadType: PayloadType.handshake,
      pageIndex: pageIndex,
      pages: pages,
      length: length - 12,
    ),
    BytePackageBitFlags(20, capabilities),
    BytePackageRaw(32, nonce),
    BytePackageRaw(32, publicX25519Key),
  ];

  @override
  int get length => 96;

  static HandshakePayload fromBytes(Uint8List bytes) => BytePackage.fromBytes(
    bytes,
    [
      ..._payloadHeaderParts(
        errorCode: 0,
        requestId: Uint8List(3),
        payloadType: PayloadType.handshake,
        pageIndex: 0,
        pages: 0,
        length: 0,
      ),
      BytePackageBitFlags(20, {}),
      BytePackageRaw(32, Uint8List(32)),
      BytePackageRaw(32, Uint8List(32)),
    ],
    (parts) => HandshakePayload._(
      protocolInitializerId: parts[0] as List<int>?,
      protocolInitializerVersion: parts[1] as int?,
      requestId: parts[3] as Uint8List,
      capabilities: parts[8] as Map<int, bool>,
      nonce: parts[9] as Uint8List,
      publicX25519Key: parts[10] as Uint8List,
    ),
  );

  @override
  HandshakePayload copyWith({Uint8List? nonce, Uint8List? publicX25519Key}) =>
      HandshakePayload(
        requestId: requestId,
        capabilities: capabilities,
        nonce: nonce ?? this.nonce,
        publicX25519Key: publicX25519Key ?? this.publicX25519Key,
      );

  /// Checks if the protocol initializer supplied in [fromBytes] matches the
  /// protocol initializer of the current implementation.
  bool initializerMatchesProtocol() =>
      const ListEquality().equals(
        protocolInitializerId,
        protocolInitializerDefaults.id,
      ) &&
      protocolInitializerVersion == protocolInitializerDefaults.version;
}

final class KeyExchangePayload extends Payload {
  @override
  String get className => "KeyExchangePayload";
  final Uint8List publicPgpKey;

  KeyExchangePayload({
    required super.requestId,
    required this.publicPgpKey,
    required super.pageIndex,
    required super.pages,
  });

  @override
  List<BytePackagePart> get parts => [
    ..._payloadHeaderParts(
      errorCode: 0,
      requestId: requestId,
      payloadType: PayloadType.keyExchange,
      pageIndex: pageIndex,
      pages: pages,
      length: publicPgpKey.length,
    ),
    BytePackageRaw(null, publicPgpKey),
  ];

  static KeyExchangePayload fromBytes(Uint8List bytes) => BytePackage.fromBytes(
    bytes,
    [
      ..._payloadHeaderParts(
        errorCode: 0,
        requestId: Uint8List(3),
        payloadType: PayloadType.keyExchange,
        pageIndex: 0,
        pages: 0,
        length: 0,
      ),
      BytePackageRaw(null, Uint8List(0)),
    ],
    (parts) => KeyExchangePayload(
      requestId: parts[3] as Uint8List,
      publicPgpKey: parts[8] as Uint8List,
      pageIndex: parts[5] as int,
      pages: parts[6] as int,
    ),
    unboundLengthIndicatorIndex: 7,
  );

  @override
  KeyExchangePayload copyWith({Uint8List? publicPgpKey}) => KeyExchangePayload(
    requestId: requestId,
    publicPgpKey: publicPgpKey ?? this.publicPgpKey,
    pageIndex: pageIndex,
    pages: pages,
  );
}

final class SignatureExchangePayload extends Payload {
  @override
  String get className => "SignatureExchangePayload";
  final Uint8List detachedSignature;

  SignatureExchangePayload({
    required super.requestId,
    required this.detachedSignature,
    required super.pageIndex,
    required super.pages,
  });

  @override
  List<BytePackagePart> get parts => [
    ..._payloadHeaderParts(
      errorCode: 0,
      requestId: requestId,
      payloadType: PayloadType.signatureExchange,
      pageIndex: pageIndex,
      pages: pages,
      length: detachedSignature.length,
    ),
    BytePackageRaw(null, detachedSignature),
  ];

  static SignatureExchangePayload fromBytes(Uint8List bytes) =>
      BytePackage.fromBytes(
        bytes,
        [
          ..._payloadHeaderParts(
            errorCode: 0,
            requestId: Uint8List(3),
            payloadType: PayloadType.signatureExchange,
            pageIndex: 0,
            pages: 0,
            length: 0,
          ),
          BytePackageRaw(null, Uint8List(0)),
        ],
        (parts) => SignatureExchangePayload(
          requestId: parts[3] as Uint8List,
          detachedSignature: parts[8] as Uint8List,
          pageIndex: parts[5] as int,
          pages: parts[6] as int,
        ),
        unboundLengthIndicatorIndex: 7,
      );

  @override
  SignatureExchangePayload copyWith({Uint8List? detachedSignature}) =>
      SignatureExchangePayload(
        requestId: requestId,
        detachedSignature: detachedSignature ?? this.detachedSignature,
        pageIndex: pageIndex,
        pages: pages,
      );
}

final class ErrorReportPayload extends Payload {
  @override
  String get className => "ErrorReportPayload";
  final int appErrorCode;
  final PayloadType errorCode;

  ErrorReportPayload({
    required super.requestId,
    required this.appErrorCode,
    required this.errorCode,
  }) : super(pageIndex: 1, pages: 1);

  @override
  List<BytePackagePart> get parts => [
    ..._payloadHeaderParts(
      errorCode: appErrorCode,
      requestId: requestId,
      payloadType: errorCode,
      pageIndex: 1,
      pages: 1,
      length: 0,
    ),
  ];

  static ErrorReportPayload fromBytes(Uint8List bytes) => BytePackage.fromBytes(
    bytes,
    [
      ..._payloadHeaderParts(
        errorCode: 0,
        requestId: Uint8List(3),
        payloadType: .error.headerIncompatible,
        pageIndex: 0,
        pages: 0,
        length: 0,
      ),
    ],
    (parts) => ErrorReportPayload(
      requestId: parts[3] as Uint8List,
      appErrorCode: parts[2] as int,
      errorCode: PayloadType._error(parts[4] as int),
    ),
  );

  @override
  ErrorReportPayload copyWith({int? appErrorCode, PayloadType? errorCode}) =>
      ErrorReportPayload(
        requestId: requestId,
        appErrorCode: appErrorCode ?? this.appErrorCode,
        errorCode: errorCode ?? this.errorCode,
      );
}
