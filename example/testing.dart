import 'dart:async';
import 'dart:typed_data';

import 'package:dart_pg/dart_pg.dart';
// import 'package:shared/src/byte_package.dart';
import 'package:shared/src/protocol_manager.dart';

final class NfcSender extends NfcSenderState {
  /// Test-only pairing: a tap simulated in [start] is routed to this receiver.
  final NfcReceiver? pairedReceiver;
  NfcSender({this.pairedReceiver});

  @override
  bool isSupported() => true;

  @override
  Future<void> start() async {
    final bytes = data!.toBytes();
    // print(bytes.toDebugString());
    final receiver = pairedReceiver;
    if (receiver == null) return;
    // broadcast events emitted before the other side's listener attaches are
    // dropped, so retry briefly, mirroring a user re-tapping the device.
    // ignore: discarded_futures
    _retryTap(receiver, bytes);
  }

  Future<void> _retryTap(NfcReceiver receiver, Uint8List bytes) async {
    for (var attempt = 0; attempt < 40; attempt++) {
      try {
        receiver.simulateTap(bytes);
      } on StateError {
        return; // the receiver was already disposed by the winning side
      }
      await Future.delayed(const Duration(milliseconds: 25));
    }
  }
}

final class NfcReceiver extends NfcReceiverState {
  @override
  Future<void> start() async {}

  /// Test-only hook simulating an incoming NFC tap from a paired sender.
  void simulateTap(Uint8List data) => emit(NfcReceiverEvent(received: data));
}

final class BluetoothSender extends BluetoothSenderState {
  /// Test-only pairing: writes are routed to this receiver's GATT server.
  final BluetoothReceiver? pairedReceiver;
  BluetoothSender({this.pairedReceiver});

  bool _connected = false;

  @override
  Future<bool> connect(String sessionId) async {
    final receiver = pairedReceiver;
    if (receiver == null || receiver.data != sessionId) return false;
    return _connected = true;
  }

  @override
  Future<void> disconnect() async => _connected = false;

  @override
  Future<bool> isConnected() async => _connected;

  @override
  Future<void> send(Uint8List data) async {
    final receiver = pairedReceiver;
    if (receiver == null || !_connected) {
      throw StateError(
        "BluetoothSender is not connected to a paired receiver.",
      );
    }
    await receiver.simulateWriteRequest(data, notificationHandler);
  }
}

final class BluetoothReceiver extends BluetoothReceiverState {
  @override
  Future<void> start() async {}

  /// Test-only hook simulating an inbound BLE write request from a paired sender.
  Future<void> simulateWriteRequest(
    Uint8List data,
    Future<void> Function(Uint8List) sendResponseWriteRequest,
  ) => readRequestHandler(data, sendResponseWriteRequest);
}

// PrivateKey.decrypt() keeps the still-encrypted ciphertext bytes for
// serialization and only exposes the decrypted material in memory, so
// encode()+PacketList.decode() would silently lose it; rebuild the secret
// key/subkey packets with s2kUsage none (plaintext) so it round-trips.
Uint8List unlockedPrivateKeyBytes(dynamic key, String passphrase) {
  final decrypted = key.decrypt(passphrase);
  final packetList = decrypted.packetList;
  for (var i = 0; i < packetList.length; i++) {
    final packet = packetList[i];
    if (packet is SecretSubkeyPacket) {
      final material = packet.secretKeyMaterial!;
      packetList[i] = SecretSubkeyPacket(
        packet.publicKey as PublicSubkeyPacket,
        material.toBytes,
        secretKeyMaterial: material,
      );
    } else if (packet is SecretKeyPacket) {
      final material = packet.secretKeyMaterial!;
      packetList[i] = SecretKeyPacket(
        packet.publicKey,
        material.toBytes,
        secretKeyMaterial: material,
      );
    }
  }
  return packetList.encode();
}

void main(List<String> args) async {
  final aNfcReceiver = NfcReceiver();
  final bNfcReceiver = NfcReceiver();
  final aBluetoothReceiver = BluetoothReceiver();
  final bBluetoothReceiver = BluetoothReceiver();

  final deviceA = ProtocolManager(
    nfcSenderState: NfcSender(pairedReceiver: bNfcReceiver),
    nfcReceiverState: aNfcReceiver,
    bluetoothSenderState: BluetoothSender(pairedReceiver: bBluetoothReceiver),
    bluetoothReceiverState: aBluetoothReceiver,
  );
  final deviceB = ProtocolManager(
    nfcSenderState: NfcSender(pairedReceiver: aNfcReceiver),
    nfcReceiverState: bNfcReceiver,
    bluetoothSenderState: BluetoothSender(pairedReceiver: aBluetoothReceiver),
    bluetoothReceiverState: bBluetoothReceiver,
  );

  deviceA.run.displayState.events.listen(
    (e) => print(
      "A: ${e.contactMode.value} role=${e.deviceRole.value} "
      "error=${e.result.value?.errorMode} "
      "failure=${e.result.value?.failureMode}",
    ),
  );
  deviceB.run.displayState.events.listen(
    (e) => print(
      "B: ${e.contactMode.value} role=${e.deviceRole.value} "
      "error=${e.result.value?.errorMode} "
      "failure=${e.result.value?.failureMode}",
    ),
  );

  // full framed OpenPGP packet-list bytes are required for both keys since
  // the protocol parses them via PacketList.decode for fingerprinting,
  // signing and verification
  // RSA is used since dart_pg 2.1.0 only implements OpenPGP signing for RSA
  // and EdDSA (whose ed25519 key generation has a flaky self-verify bug)
  final keyA = OpenPGP.generateKey(
    ['Device A <a@example.com>'],
    'passphraseA',
    type: KeyType.rsa,
  );
  final keyB = OpenPGP.generateKey(
    ['Device B <b@example.com>'],
    'passphraseB',
    type: KeyType.rsa,
  );
  final pgpPublicKeyA = keyA.publicKey.packetList.encode();
  final pgpPrivateKeyA = unlockedPrivateKeyBytes(keyA, 'passphraseA');
  final pgpPublicKeyB = keyB.publicKey.packetList.encode();
  final pgpPrivateKeyB = unlockedPrivateKeyBytes(keyB, 'passphraseB');

  await Future.wait(
    [
      deviceA.start(pgpPublicKeyA, pgpPrivateKeyA),
      deviceB.start(pgpPublicKeyB, pgpPrivateKeyB),
    ],
    eagerError: true,
  ).timeout(const Duration(seconds: 5), onTimeout: () => const []);

  print(
    "Device A role: ${deviceA.run.displayState.lastEvent?.deviceRole.value}",
  );
  print(
    "Device B role: ${deviceB.run.displayState.lastEvent?.deviceRole.value}",
  );

  deviceA.close();
  deviceB.close();
}
