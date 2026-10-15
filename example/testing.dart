import 'dart:async';
import 'dart:typed_data';

import 'package:dart_pg/dart_pg.dart';
import 'package:shared/shared.dart';

final class NfcSender extends NfcSenderState {
  /// Test-only pairing: a tap simulated in [start] is routed to this receiver.
  final NfcReceiver? pairedReceiver;
  final bool available;
  NfcSender({this.pairedReceiver, this.available = true});

  @override
  bool isAvailable() => available;

  @override
  Future<void> start() async {
    final bytes = data!.toBytes();
    final receiver = pairedReceiver;
    if (receiver == null) return;
    // broadcast events emitted before the other side's listener attaches are
    // dropped, so retry briefly, mirroring a user re-tapping the device.
    // ignore: discarded_futures
    _retryTap(receiver, bytes);
  }

  /// Test-only hook simulating a reader selecting this device's card.
  void simulateSelected() => emit(NfcSenderEvent.selected());

  Future<void> _retryTap(NfcReceiver receiver, Uint8List bytes) async {
    for (var attempt = 0; attempt < 40; attempt++) {
      try {
        emit(NfcSenderEvent.selected());
        receiver.simulateTap(bytes);
        // the disposed StreamController surfaces as a StateError; used here
        // as an intentional signal rather than an exceptional condition
        // ignore: avoid_catching_errors
      } on StateError {
        return; // the receiver was already disposed by the winning side
      }
      await Future.delayed(const Duration(milliseconds: 25));
    }
  }
}

final class NfcReceiver extends NfcReceiverState {
  @override
  bool isAvailable() => true;

  @override
  Future<void> start() async {}

  /// Test-only hook simulating an incoming NFC tap from a paired sender.
  void simulateTap(Uint8List data) => emit(NfcReceiverEvent(received: data));
}

final class BluetoothSender extends BluetoothSenderState {
  /// Test-only pairing: writes are routed to this receiver's GATT server.
  final BluetoothReceiver? pairedReceiver;

  /// Test-only: simulates the devices being moved apart (connection lost)
  /// once this many writes have been sent.
  final int? dropAfterSends;

  /// Test-only: modifies every notification (server response) before it
  /// reaches this sender.
  final Uint8List Function(Uint8List)? tamperResponses;
  BluetoothSender({
    this.pairedReceiver,
    this.dropAfterSends,
    this.tamperResponses,
  });

  bool _connected = false;
  int _sends = 0;

  @override
  Future<bool> connect(String sessionId) async {
    final receiver = pairedReceiver;
    if (receiver == null || receiver.data != sessionId) return false;
    receiver._connectedSender = this;
    return _connected = true;
  }

  /// Test-only hook simulating the paired receiver (server) disconnecting.
  void simulatePeripheralLost() {
    _connected = false;
    peripheralDisconnected();
  }

  @override
  Future<void> disconnect() async {
    if (_connected) pairedReceiver?.simulateDisconnect(central: this);
    _connected = false;
  }

  @override
  Future<bool> isConnected() async => _connected;

  @override
  Future<void> send(Uint8List data) async {
    final receiver = pairedReceiver;
    final dropAfter = dropAfterSends;
    if (dropAfter != null && _sends >= dropAfter && _connected) {
      _connected = false;
      receiver?.simulateDisconnect(central: this);
    }
    _sends++;
    if (receiver == null || !_connected) {
      throw StateError(
        "BluetoothSender is not connected to a paired receiver.",
      );
    }
    final tamper = tamperResponses;
    await receiver.simulateWriteRequest(
      data,
      tamper == null
          ? notificationHandler
          : (response) => notificationHandler(tamper(response)),
      central: this,
    );
  }

  @override
  bool isAvailable() => true;
}

final class BluetoothReceiver extends BluetoothReceiverState {
  /// Test-only: simulates the devices being moved apart (connection lost)
  /// instead of handling the request once this many have been handled.
  final int? dropAfterRequests;
  BluetoothReceiver({this.dropAfterRequests});

  BluetoothSender? _connectedSender;
  int _requests = 0;

  @override
  Future<void> start() async {}

  /// Test-only hook simulating an inbound BLE write request from a paired sender.
  Future<void> simulateWriteRequest(
    Uint8List data,
    Future<void> Function(Uint8List) sendResponseWriteRequest, {
    Object? central,
  }) async {
    final dropAfter = dropAfterRequests;
    if (dropAfter != null && _requests >= dropAfter) {
      _connectedSender?.simulatePeripheralLost();
      simulateDisconnect(central: central);
      return;
    }
    _requests++;
    await readRequestHandler(data, sendResponseWriteRequest, central: central);
  }

  /// Test-only hook simulating the paired sender disconnecting.
  void simulateDisconnect({Object? central}) =>
      centralDisconnected(central: central);
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

  String debugFormatAdditionalInfo(String additionalInfo) {
    String decimalToHex(String value) =>
        int.parse(value).toRadixString(16).padLeft(2, "0").toUpperCase();

    var tmp = additionalInfo;
    tmp = tmp.replaceAllMapped(
      RegExp(r"(?<=fingerprint: \[).*?(?=\])"),
      (m) => m.group(0)!.split(", ").map(decimalToHex).join(", "),
    );
    tmp = tmp.replaceAllMapped(
      RegExp(r"(?<=userIds: \{).*?(?=\})"),
      (m) => m.group(0)!.split(", ").map(UserId.tryParse).join(", "),
    );
    return tmp;
  }

  deviceA.run.displayState.events.listen(
    (e) => print(
      "A: ${e.contactMode.value} role=${e.deviceRole.value} "
      "error=${e.result.value?.errorMode} "
      "failure=${e.result.value?.failureMode} "
      "additionalInfo=${debugFormatAdditionalInfo((e.result.value?.additionalInfo).toString())}",
    ),
  );
  deviceB.run.displayState.events.listen(
    (e) => print(
      "B: ${e.contactMode.value} role=${e.deviceRole.value} "
      "error=${e.result.value?.errorMode} "
      "failure=${e.result.value?.failureMode} "
      "additionalInfo=${debugFormatAdditionalInfo((e.result.value?.additionalInfo).toString())}",
    ),
  );

  // full framed OpenPGP packet-list bytes are required for both keys since
  // the protocol parses them via PacketList.decode for fingerprinting,
  // signing and verification
  // RSA is used since dart_pg 2.1.0 only implements OpenPGP signing for RSA
  // and EdDSA (whose ed25519 key generation has a flaky self-verify bug)
  final keyA = OpenPGP.generateKey(
    ["Device A (Never gonna) <a@example.com>"],
    "passphraseA",
    type: KeyType.rsa,
  );
  final keyB = OpenPGP.generateKey(
    ["Device B (Give you up) <b@example.com>"],
    "passphraseB",
    type: KeyType.rsa,
  );
  final pgpPublicKeyA = keyA.publicKey.packetList.encode();
  final pgpPrivateKeyA = keyA.packetList.encode();
  final pgpPublicKeyB = keyB.publicKey.packetList.encode();
  final pgpPrivateKeyB = keyB.packetList.encode();

  await Future.wait(
    [
      deviceA.start(
        LocalPgpProvider(pgpPublicKeyA, pgpPrivateKeyA),
        privateKeyPassphrase: "passphraseA",
      ),
      deviceB.start(
        LocalPgpProvider(pgpPublicKeyB, pgpPrivateKeyB),
        privateKeyPassphrase: "passphraseB",
      ),
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
