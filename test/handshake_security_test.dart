import 'dart:async';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' hide PublicKey, Signature;
import 'package:dart_pg/dart_pg.dart' hide Uint8ListExt;
import 'package:shared/shared.dart';
import 'package:test/test.dart';

import '../example/testing.dart';

/// The BLE server before any authentication: a device in radio range must
/// neither be able to start a session without NFC contact, nor to abort or
/// hijack one.
void main() {
  late PrivateKey key;

  setUpAll(() {
    key = OpenPGP.generateKey(
      ['Victim <v@example.com>'],
      'pw',
      type: KeyType.rsa,
    ) as PrivateKey;
  });

  final peerRequestId = Uint8List.fromList([9, 9, 9]);
  final capabilities = {0: true, 1: true, 2: false};

  Future<SimplePublicKey> newPublicKey() async =>
      (await X25519().newKeyPair()).extractPublicKey();

  Uint8List handshake(Uint8List nonce, List<int> publicKey) => HandshakePayload(
    requestId: peerRequestId,
    capabilities: capabilities,
    nonce: nonce,
    publicX25519Key: Uint8List.fromList(publicKey),
  ).toBytes();

  Uint8List errorReport() => ErrorReportPayload(
    requestId: peerRequestId,
    appErrorCode: 1,
    errorCode: PayloadType.error.unableToReadContent,
  ).toBytes();

  late ProtocolManager manager;
  late BluetoothReceiver bluetooth;
  late NfcSender nfcSender;
  late NfcReceiver nfcReceiver;
  late List<DisplayEvent> events;
  late List<Payload> responses;

  Future<void> respond(Uint8List data) async =>
      responses.add(Payload.fromBytes(data));

  Future<void> startServer() async {
    bluetooth = BluetoothReceiver();
    nfcSender = NfcSender();
    nfcReceiver = NfcReceiver();
    manager = ProtocolManager(
      nfcSenderState: nfcSender,
      nfcReceiverState: nfcReceiver,
      bluetoothSenderState: BluetoothSender(),
      bluetoothReceiverState: bluetooth,
    );
    events = [];
    responses = [];
    manager.run.displayState.events.listen(events.add);
    // the run ends on its own after the protocol timeout; tests don't wait
    // ignore: discarded_futures
    manager
        .start(
          key.publicKey.packetList.encode(),
          key.packetList.encode(),
          privateKeyPassphrase: 'pw',
        )
        .ignore();
    while (!events.any((e) => e.contactMode.value == .tapOther)) {
      await Future.delayed(const Duration(milliseconds: 20));
    }
    await Future.delayed(const Duration(milliseconds: 50));
  }

  bool claimed() => events.any((e) => e.deviceRole.value != null);
  bool finished() => events.any((e) => e.contactMode.value == .done);

  Future<void> settle() => Future.delayed(const Duration(milliseconds: 100));

  tearDown(() => manager.close());

  test('a handshake without any NFC contact is rejected', () async {
    await startServer();
    await bluetooth.simulateWriteRequest(
      handshake(Uint8List(32), (await newPublicKey()).bytes),
      respond,
      central: 'attacker',
    );
    await settle();

    expect(responses.single, isA<ErrorReportPayload>());
    expect(claimed(), isFalse);
    expect(finished(), isFalse);
  });

  test('low-order X25519 keys are rejected even after NFC contact', () async {
    await startServer();
    nfcSender.simulateSelected();
    await settle();

    for (final point in [
      Uint8List(32),
      Uint8List(32)..[0] = 1,
      Uint8List.fromList([
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, //
        0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32,
        0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
      ]),
    ]) {
      await bluetooth.simulateWriteRequest(
        handshake(Uint8List(32), point),
        respond,
        central: 'attacker',
      );
    }
    await settle();

    expect(responses, hasLength(3));
    expect(responses, everyElement(isA<ErrorReportPayload>()));
    expect(claimed(), isFalse);
  });

  test('a valid handshake after NFC contact is accepted', () async {
    await startServer();
    nfcSender.simulateSelected();
    await settle();
    await bluetooth.simulateWriteRequest(
      handshake(Uint8List(32), (await newPublicKey()).bytes),
      respond,
      central: 'client',
    );
    await settle();

    expect(responses.single, isA<HandshakeResponsePayload>());
    expect(events.last.deviceRole.value, ProtocolRole.serverSender);
  });

  test(
    'unauthenticated garbage and error reports do not end the run',
    () async {
      await startServer();
      nfcSender.simulateSelected();
      await settle();

      await bluetooth.simulateWriteRequest(
        errorReport(),
        respond,
        central: 'a',
      );
      await bluetooth.simulateWriteRequest(
        Uint8List.fromList(List.filled(40, 0xAB)),
        respond,
        central: 'a',
      );
      await bluetooth.simulateWriteRequest(
        Uint8List.fromList([0x50, 0x54, 1]),
        respond,
        central: 'a',
      );
      await settle();
      expect(finished(), isFalse);

      // and a genuine client can still connect afterwards
      await bluetooth.simulateWriteRequest(
        handshake(Uint8List(32), (await newPublicKey()).bytes),
        respond,
        central: 'client',
      );
      await settle();
      expect(events.last.deviceRole.value, ProtocolRole.serverSender);
    },
  );

  test('after the handshake, other centrals are ignored', () async {
    await startServer();
    nfcSender.simulateSelected();
    await settle();
    await bluetooth.simulateWriteRequest(
      handshake(Uint8List(32), (await newPublicKey()).bytes),
      respond,
      central: 'client',
    );
    await settle();

    await bluetooth.simulateWriteRequest(
      errorReport(),
      respond,
      central: 'attacker',
    );
    bluetooth.simulateDisconnect(central: 'attacker');
    await settle();
    expect(finished(), isFalse);

    // the bound client still can
    await bluetooth.simulateWriteRequest(
      errorReport(),
      respond,
      central: 'client',
    );
    await settle();
    expect(finished(), isTrue);
  });

  test('the handshake must match the bootstrap received over NFC', () async {
    await startServer();
    final peerKey = await newPublicKey();
    final peerNonce = Uint8List.fromList(List.generate(32, (i) => i + 1));
    // a random byte of 0 always loses against ours, so we become the server
    nfcReceiver.simulateTap(
      NfcBootstrap(
        random: 0,
        sessionId: Uint8List(16),
        capabilities: capabilities,
        nonce: peerNonce,
        publicX25519Key: Uint8List.fromList(peerKey.bytes),
      ).toBytes(),
    );
    await settle();
    expect(events.last.deviceRole.value, ProtocolRole.serverSender);

    // another device in range, with a perfectly valid key of its own
    await bluetooth.simulateWriteRequest(
      handshake(peerNonce, (await newPublicKey()).bytes),
      respond,
      central: 'attacker',
    );
    await bluetooth.simulateWriteRequest(
      handshake(Uint8List(32), peerKey.bytes),
      respond,
      central: 'attacker',
    );
    await settle();
    expect(responses, hasLength(2));
    expect(responses, everyElement(isA<ErrorReportPayload>()));

    await bluetooth.simulateWriteRequest(
      handshake(peerNonce, peerKey.bytes),
      respond,
      central: 'client',
    );
    await settle();
    expect(responses.last, isA<HandshakeResponsePayload>());
    expect(finished(), isFalse);
  });
}
