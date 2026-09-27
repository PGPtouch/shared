import 'dart:typed_data';

import 'package:shared/src/packages.dart';
import 'package:test/test.dart';

void main() {
  test('round-trips NfyBootstrap', () {
    final package = NfcBootstrap(
      random: 7,
      sessionId: Uint8List.fromList(List.generate(16, (index) => index)),
      capabilities: {0: true, 9: true},
      nonce: Uint8List.fromList(List.generate(32, (index) => index + 1)),
      publicX25519Key: Uint8List(32),
    );

    final decoded = NfcBootstrap.fromBytes(package.toBytes());
    expect(decoded.random, package.random);
    expect(decoded.sessionId, orderedEquals(package.sessionId));
    expect(decoded.capabilities[0], isTrue);
    expect(decoded.capabilities[9], isTrue);
    expect(decoded.nonce, orderedEquals(package.nonce));
    expect(decoded.publicX25519Key, orderedEquals(package.publicX25519Key));
  });

  test('round-trips HandshakePayload and bit flags', () {
    final package = HandshakePayload(
      requestId: Uint8List.fromList([1, 2, 3]),
      capabilities: {0: true, 19: true},
      nonce: Uint8List.fromList(List.generate(32, (index) => index)),
      publicX25519Key: Uint8List.fromList(
        List.generate(32, (index) => 31 - index),
      ),
    );

    final decoded = HandshakePayload.fromBytes(package.toBytes());
    expect(decoded.requestId, orderedEquals(package.requestId));
    expect(decoded.capabilities[0], isTrue);
    expect(decoded.capabilities[19], isTrue);
    expect(decoded.pageIndex, 1);
    expect(decoded.pages, 1);
    expect(decoded.nonce, orderedEquals(package.nonce));
    expect(decoded.publicX25519Key, orderedEquals(package.publicX25519Key));
  });

  test('round-trips variable-length key exchange payload', () {
    final package = KeyExchangePayload(
      requestId: Uint8List.fromList([4, 5, 6]),
      publicPgpKey: Uint8List.fromList([7, 8, 9, 10, 11]),
      pageIndex: 1,
      pages: 3,
    );

    final decoded = KeyExchangePayload.fromBytes(package.toBytes());
    expect(decoded.publicPgpKey, orderedEquals(package.publicPgpKey));
    expect(decoded.pageIndex, 1);
    expect(decoded.pages, 3);
  });

  test('round-trips variable-length signature exchange payload', () {
    final package = SignatureExchangePayload(
      requestId: Uint8List.fromList([12, 13, 14]),
      detachedSignature: Uint8List.fromList([15, 16, 17, 18]),
      pageIndex: 2,
      pages: 4,
    );

    final decoded = SignatureExchangePayload.fromBytes(package.toBytes());
    expect(decoded.detachedSignature, orderedEquals(package.detachedSignature));
    expect(decoded.pageIndex, 2);
    expect(decoded.pages, 4);
  });

  test('round-trips and dispatches error payload', () {
    final package = ErrorReportPayload(
      requestId: Uint8List.fromList([19, 20, 21]),
      appErrorCode: 3,
      errorCode: PayloadType.error.pageTimeout,
    );

    final decoded = Payload.fromBytes(package.toBytes());
    expect(decoded, isA<ErrorReportPayload>());
    final error = decoded as ErrorReportPayload;
    expect(error.requestId, orderedEquals(package.requestId));
    expect(error.appErrorCode, 3);
    expect(error.errorCode, PayloadType.error.pageTimeout);
  });
}
