import 'dart:typed_data';

import 'package:dart_pg/dart_pg.dart' hide Uint8ListExt;
import 'package:shared/src/packages.dart';
import 'package:shared/src/protocol_manager.dart';
import 'package:shared/src/user_id.dart';
import 'package:test/test.dart';

void main() {
  signatureTests();
  test('user IDs are parsed in linear time', () {
    final sw = Stopwatch()..start();
    expect(UserId.tryParse(' ' * 100000), isNull);
    expect(UserId.tryParse('a${' ' * 100000}('), isNull);
    expect(sw.elapsedMilliseconds, lessThan(1000));
    final parsed = UserId.parse('John Doe (Developer) <john@example.com>');
    expect(parsed.name, 'John Doe');
    expect(parsed.comment, 'Developer');
    expect(parsed.email, 'john@example.com');
    expect(UserId.parse('<a@b.c>').name, isNull);
  });

  test(
    'unknown capability bits are kept and agree across both wire formats',
    () {
      final bits = {0: true, 1: true, 2: true, 40: true, 100: true};
      final bootstrap = NfcBootstrap.fromBytes(
        NfcBootstrap(
          random: 1,
          sessionId: Uint8List(16),
          capabilities: {
            for (final e in bits.entries)
              if (e.key < 96) e.key: true,
          },
          nonce: Uint8List(32),
          publicX25519Key: Uint8List(32),
        ).toBytes(),
      );
      final handshake = HandshakePayload.fromBytes(
        HandshakePayload(
          requestId: Uint8List(3),
          capabilities: bits,
          nonce: Uint8List(32),
          publicX25519Key: Uint8List(32),
        ).toBytes(),
      );

      final viaBootstrap = Capabilities.fromMap(bootstrap.capabilities);
      final viaHandshake = Capabilities.fromMap(handshake.capabilities);
      expect(viaBootstrap.additional[40], isTrue);
      expect(viaHandshake.additional[100], isTrue);
      expect(
        Capabilities.fromMap({0: true, 40: true, 150: false}).toInt(),
        Capabilities.fromMap({0: true, 40: true}).toInt(),
      );
      expect(Capabilities.fromMap({40: true}).toInt(), 1 << 40);
    },
  );

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

void signatureTests() {
  group('verifyTranscriptSignature', () {
    final key =
        OpenPGP.generateKey(['Test <test@example.com>'], 'pw') as PrivateKey;
    final otherKey =
        OpenPGP.generateKey(['Other <other@example.com>'], 'pw') as PrivateKey;
    final publicKey = Uint8List.fromList(key.publicKey.packetList.encode());
    const transcript = 'session\nnonce';

    Uint8List sign(String text, DateTime time, PrivateKey signer) =>
        Uint8List.fromList(
          CleartextMessage(text)
              .signDetached([signer], time: time)
              .packetList
              .encode(),
        );

    test('accepts signatures from a clock that is ahead', () {
      final signature = sign(
        transcript,
        DateTime.now().add(const Duration(minutes: 5)),
        key,
      );
      final result = verifyTranscriptSignature(
        transcript,
        publicKey,
        signature,
      );
      expect(result.isVerified, isTrue);
      expect(result.userIds, contains('Test <test@example.com>'));
    });

    test('rejects a different transcript', () {
      final signature = sign('other', DateTime.now(), key);
      expect(
        verifyTranscriptSignature(transcript, publicKey, signature).isVerified,
        isFalse,
      );
    });

    test('rejects a signature with corrupted signature material', () {
      final signature = sign(transcript, DateTime.now(), key);
      signature[signature.length - 1] ^= 0xff;
      final result = verifyTranscriptSignature(
        transcript,
        publicKey,
        signature,
      );
      expect(result.isVerified, isFalse);
      expect(result.verificationError, isNotEmpty);
    });

    test('rejects a signature from a different key', () {
      final signature = sign(transcript, DateTime.now(), otherKey);
      expect(
        verifyTranscriptSignature(transcript, publicKey, signature).isVerified,
        isFalse,
      );
    });
  });
}
