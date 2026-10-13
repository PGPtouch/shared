import 'dart:async';
import 'dart:typed_data';

import 'package:dart_pg/dart_pg.dart' hide Uint8ListExt;
import 'package:shared/src/packages.dart';
import 'package:shared/src/pgp_provider.dart';
import 'package:shared/src/protocol_manager.dart';
import 'package:test/test.dart';

import '../example/testing.dart';

typedef _Device = ({
  ProtocolManager manager,
  List<DisplayEvent> events,
  Uint8List publicKey,
  Uint8List privateKey,
});

// emit is protected because only the protocol manager is meant to drive it
// ignore: invalid_use_of_protected_member
void emit(DisplayState state, DisplayEvent event) => state.emit(event);

void main() {
  decideRoleTests();
  displayStateTests();
  bluetoothSenderStateTests();
  protocolRunTests();
}

void decideRoleTests() {
  group('decideRole', () {
    final low = Uint8List.fromList(List.filled(32, 1));
    final high = Uint8List.fromList(List.filled(32, 2));

    RoleDecision decide(
      int self,
      Uint8List nonceSelf,
      int other,
      Uint8List o,
    ) => decideRole(
      randomSelf: self,
      nonceSelf: nonceSelf,
      randomOther: other,
      nonceOther: o,
    );

    test('the higher random byte becomes the server', () {
      expect(decide(9, low, 3, high), RoleDecision.serverSender);
      expect(decide(3, high, 9, low), RoleDecision.clientReceiver);
    });

    test('equal random bytes are decided by the nonce', () {
      expect(decide(5, high, 5, low), RoleDecision.serverSender);
      expect(decide(5, low, 5, high), RoleDecision.clientReceiver);
    });

    test('only equal random bytes and nonces are undecidable', () {
      expect(
        decide(5, low, 5, Uint8List.fromList(low)),
        RoleDecision.undecidable,
      );
    });

    test('exactly one of two devices becomes the server', () {
      for (final (a, b) in [(1, 2), (2, 1), (7, 7)]) {
        final first = decide(a, low, b, high);
        final second = decide(b, high, a, low);
        expect(
          {first, second},
          {RoleDecision.serverSender, RoleDecision.clientReceiver},
        );
      }
    });
  });
}

void displayStateTests() {
  group('DisplayState', () {
    DisplayResult result() =>
        DisplayResult(mode: .success, errorMode: null, failureMode: null);

    test('ignores events after the run is done', () {
      final state = DisplayState();
      emit(state, state.withChanges(null, .holdOther, null));
      emit(state, state.withChanges(.serverSender, .done, result()));
      emit(state, state.withChanges(null, .holdOther, null));
      emit(
        state,
        state.withChanges(
          null,
          .done,
          DisplayResult(
            mode: .failure,
            errorMode: null,
            failureMode: .connectionFailed,
          ),
        ),
      );

      expect(state.lastEvent!.contactMode.value, DisplayContactMode.done);
      expect(state.lastEvent!.result.value!.mode, DisplayMode.success);
    });

    test('a new run may start after a finished one', () {
      final state = DisplayState();
      emit(state, state.withChanges(null, .done, result()));
      emit(state, state.withChanges(null, .initializing, null));
      expect(
        state.lastEvent!.contactMode.value,
        DisplayContactMode.initializing,
      );
    });

    test('ignores events after disposal instead of throwing', () async {
      final state = DisplayState();
      await state.dispose();
      expect(
        () => emit(state, state.withChanges(null, .holdOther, null)),
        returnsNormally,
      );
    });

    test('hasChanged only reports actual changes', () {
      final state = DisplayState();
      final first = state.withChanges(null, .tapOther, null);
      expect(first.deviceRole.hasChanged, isTrue);
      emit(state, first);

      final second = state.withChanges(null, .holdOther, null);
      expect(second.deviceRole.hasChanged, isFalse);
      expect(second.contactMode.hasChanged, isTrue);
      expect(second.result.hasChanged, isFalse);
      emit(state, second);

      final third = state.withChanges(.clientReceiver, .holdOther, null);
      expect(third.deviceRole.hasChanged, isTrue);
      expect(third.contactMode.hasChanged, isFalse);
    });
  });
}

final class _TestBluetoothSender extends BluetoothSenderState {
  final sent = <Uint8List>[];

  @override
  Duration get pageTimeout => const Duration(milliseconds: 50);

  @override
  Future<bool> connect(String sessionId) async => true;
  @override
  Future<void> disconnect() async {}
  @override
  Future<bool> isConnected() async => true;
  @override
  Future<void> send(Uint8List data) async => sent.add(data);
  @override
  bool isAvailable() => true;

  Future<void> deliver(Uint8List data) => notificationHandler(data);

  void lose() => peripheralDisconnected();

  void reconnect() => resetConnectionLoss();
}

final class _TestBluetoothReceiver extends BluetoothReceiverState {
  @override
  Duration get pageTimeout => const Duration(milliseconds: 50);

  @override
  Future<void> start() async {}

  Future<void> deliver(
    Uint8List data,
    Future<void> Function(Uint8List) respond,
  ) => readRequestHandler(data, respond);
}

void bluetoothSenderStateTests() {
  group('page timeouts', () {
    final requestId = Uint8List.fromList([1, 2, 3]);
    final firstOfTwoPages = KeyExchangePayload(
      requestId: requestId,
      publicPgpKey: Uint8List.fromList([1]),
      pageIndex: 1,
      pages: 2,
    ).toBytes();

    void expectPageTimeoutReport(Uint8List bytes) {
      final report = Payload.fromBytes(bytes) as ErrorReportPayload;
      expect(report.errorCode, PayloadType.error.pageTimeout);
      expect(report.requestId, orderedEquals(requestId));
    }

    test('disposing cancels pending page timeouts', () async {
      final receiver = _TestBluetoothReceiver();
      final responses = <Uint8List>[];
      await receiver.deliver(firstOfTwoPages, (data) async {
        responses.add(data);
      });
      await receiver.dispose();

      final sender = _TestBluetoothSender();
      await sender.deliver(firstOfTwoPages);
      await sender.dispose();

      await Future<void>.delayed(const Duration(milliseconds: 150));
      expect(responses, isEmpty);
      expect(sender.sent, isEmpty);
    });

    test('a completed multi-page request does not time out', () async {
      final receiver = _TestBluetoothReceiver();
      final responses = <Uint8List>[];
      Future<void> respond(Uint8List data) async => responses.add(data);
      await receiver.deliver(firstOfTwoPages, respond);
      await receiver.deliver(
        KeyExchangePayload(
          requestId: requestId,
          publicPgpKey: Uint8List.fromList([2]),
          pageIndex: 2,
          pages: 2,
        ).toBytes(),
        respond,
      );

      await Future<void>.delayed(const Duration(milliseconds: 150));
      expect(responses, isEmpty);
      await receiver.dispose();
    });

    test('the receiver drops a stalled request and reports it', () async {
      final receiver = _TestBluetoothReceiver();
      final responses = <Uint8List>[];
      await receiver.deliver(firstOfTwoPages, (data) async {
        responses.add(data);
      });
      expect(responses, isEmpty);

      await Future<void>.delayed(const Duration(milliseconds: 150));
      expect(responses, hasLength(1));
      expectPageTimeoutReport(responses.single);
      await receiver.dispose();
    });

    test('the sender drops a stalled response and reports it', () async {
      final sender = _TestBluetoothSender();
      final response = sender.receiveRequestIdResponse(0x010203);
      final expectation = expectLater(
        response,
        throwsA(isA<TimeoutException>()),
      );
      await sender.deliver(firstOfTwoPages);

      await expectation;
      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(sender.sent, hasLength(1));
      expectPageTimeoutReport(sender.sent.single);
      await sender.dispose();
    });
  });

  group('BluetoothSenderState', () {
    final requestId = Uint8List.fromList([1, 2, 3]);
    Uint8List page(int index, int pages) => KeyExchangePayload(
      requestId: requestId,
      publicPgpKey: Uint8List.fromList([index]),
      pageIndex: index,
      pages: pages,
    ).toBytes();

    test('reassembles pages and tolerates a repeated final page', () async {
      final sender = _TestBluetoothSender();
      final response = sender.receiveRequestIdResponse(0x010203);
      await sender.deliver(page(2, 2));
      await sender.deliver(page(1, 2));
      final payload = Payload.fromBytes(await response) as KeyExchangePayload;
      expect(payload.publicPgpKey, orderedEquals([1, 2]));
      await expectLater(sender.deliver(page(1, 2)), completes);
      await sender.dispose();
    });

    test(
      'the handshake response is header-only with an empty content',
      () async {
        final bytes = HandshakeResponsePayload(requestId: requestId).toBytes();
        expect(bytes, hasLength(12));
        expect(bytes.sublist(0, 2), [0x50, 0x54]);
        expect(bytes[3], 0); // no error
        expect(bytes[7], 0); // handshake type
        expect(bytes.sublist(10, 12), [0, 0]); // empty content

        final decoded = Payload.fromBytes(bytes);
        expect(decoded, isA<HandshakeResponsePayload>());
        expect(decoded.requestId, orderedEquals(requestId));

        final sender = _TestBluetoothSender();
        final response = sender.receiveRequestIdResponse(0x010203);
        await sender.deliver(bytes);
        expect(await response, orderedEquals(bytes));
        await sender.dispose();
      },
    );

    test('dispose releases a pending response with an error', () async {
      final sender = _TestBluetoothSender();
      final response = sender.receiveRequestIdResponse(42);
      final expectation = expectLater(response, throwsStateError);
      await sender.dispose();
      await expectation;
    });

    group('connection loss', () {
      test('releases a pending response with an error', () async {
        final sender = _TestBluetoothSender();
        final response = sender.receiveRequestIdResponse(42);
        final expectation = expectLater(response, throwsStateError);
        sender.lose();
        await expectation;
        await sender.dispose();
      });

      test('fails responses awaited after the loss', () async {
        final sender = _TestBluetoothSender()..lose();
        await expectLater(
          sender.receiveRequestIdResponse(42),
          throwsStateError,
        );
        await sender.dispose();
      });

      test('keeps a response that arrived before the loss', () async {
        final sender = _TestBluetoothSender();
        await sender.deliver(page(1, 1));
        sender.lose();
        final payload = Payload.fromBytes(
          await sender.receiveRequestIdResponse(0x010203),
        ) as KeyExchangePayload;
        expect(payload.publicPgpKey, orderedEquals([1]));
        await sender.dispose();
      });

      test('a new connection accepts responses again', () async {
        final sender = _TestBluetoothSender()
          ..lose()
          ..reconnect();
        final response = sender.receiveRequestIdResponse(0x010203);
        await sender.deliver(page(1, 1));
        expect(Payload.fromBytes(await response), isA<KeyExchangePayload>());
        await sender.dispose();
      });
    });
  });
}

void protocolRunTests() {
  group('protocol run', () {
    late PrivateKey keyA;
    late PrivateKey keyB;

    setUpAll(() {
      keyA = OpenPGP.generateKey(
        ['Device A <a@example.com>'],
        'passphraseA',
        type: KeyType.rsa,
      ) as PrivateKey;
      keyB = OpenPGP.generateKey(
        ['Device B <b@example.com>'],
        'passphraseB',
        type: KeyType.rsa,
      ) as PrivateKey;
    });

    (_Device, _Device) createDevices({
      bool aCanSendNfc = true,
      int? aDropsBluetoothAfter,
      Uint8List Function(Uint8List)? aTamperResponses,
      int? bDropsBluetoothAfterRequests,
    }) {
      final aNfcReceiver = NfcReceiver();
      final bNfcReceiver = NfcReceiver();
      final aBluetoothReceiver = BluetoothReceiver();
      final bBluetoothReceiver = BluetoothReceiver(
        dropAfterRequests: bDropsBluetoothAfterRequests,
      );

      _Device build(ProtocolManager manager, PrivateKey key) {
        final events = <DisplayEvent>[];
        manager.run.displayState.events.listen(events.add);
        return (
          manager: manager,
          events: events,
          publicKey: key.publicKey.packetList.encode(),
          privateKey: key.packetList.encode(),
        );
      }

      return (
        build(
          ProtocolManager(
            nfcSenderState: NfcSender(
              pairedReceiver: bNfcReceiver,
              available: aCanSendNfc,
            ),
            nfcReceiverState: aNfcReceiver,
            bluetoothSenderState: BluetoothSender(
              pairedReceiver: bBluetoothReceiver,
              dropAfterSends: aDropsBluetoothAfter,
              tamperResponses: aTamperResponses,
            ),
            bluetoothReceiverState: aBluetoothReceiver,
          ),
          keyA,
        ),
        build(
          ProtocolManager(
            nfcSenderState: NfcSender(pairedReceiver: aNfcReceiver),
            nfcReceiverState: bNfcReceiver,
            bluetoothSenderState: BluetoothSender(
              pairedReceiver: aBluetoothReceiver,
            ),
            bluetoothReceiverState: bBluetoothReceiver,
          ),
          keyB,
        ),
      );
    }

    Future<void> start(_Device device, String passphrase) =>
        device.manager.start(
          LocalPgpProvider(device.publicKey, device.privateKey),
          privateKeyPassphrase: passphrase,
        );

    test('both devices succeed with opposite roles', () async {
      final (a, b) = createDevices();
      final aPublicKey = Uint8List.fromList(a.publicKey);
      final bPublicKey = Uint8List.fromList(b.publicKey);

      await Future.wait([start(a, 'passphraseA'), start(b, 'passphraseB')])
          .timeout(const Duration(seconds: 30));

      final aResult = a.events.last;
      final bResult = b.events.last;
      expect(aResult.contactMode.value, DisplayContactMode.done);
      expect(bResult.contactMode.value, DisplayContactMode.done);
      expect(aResult.result.value!.mode, DisplayMode.success);
      expect(bResult.result.value!.mode, DisplayMode.success);
      expect(
        {aResult.deviceRole.value, bResult.deviceRole.value},
        {ProtocolRole.serverSender, ProtocolRole.clientReceiver},
      );

      // each device learned the other one's key
      expect(aResult.result.value!.additionalInfo.pgpKey, bPublicKey);
      expect(bResult.result.value!.additionalInfo.pgpKey, aPublicKey);

      // exactly one terminal event, and the role is known from the first
      // moment of contact on
      for (final device in [a, b]) {
        expect(
          device.events.where((e) => e.contactMode.value == .done),
          hasLength(1),
        );
        final contact = device.events.where(
          (e) => e.contactMode.value == .holdOther,
        );
        expect(contact, isNotEmpty);
        // hold is only shown once the role is established
        expect(contact.map((e) => e.deviceRole.value), everyElement(isNotNull));
      }
      expect(
        [a, b].map((d) => d.events.last.deviceRole.value),
        everyElement(isNotNull),
      );

      await a.manager.close();
      await b.manager.close();
    });

    test('a device that cannot emit NFC always becomes the client', () async {
      final (a, b) = createDevices(aCanSendNfc: false);

      await Future.wait([start(a, 'passphraseA'), start(b, 'passphraseB')])
          .timeout(const Duration(seconds: 30));

      expect(a.events.last.deviceRole.value, ProtocolRole.clientReceiver);
      expect(b.events.last.deviceRole.value, ProtocolRole.serverSender);
      expect(a.events.last.result.value!.mode, DisplayMode.success);
      expect(b.events.last.result.value!.mode, DisplayMode.success);

      await a.manager.close();
      await b.manager.close();
    });

    test(
      'losing the connection mid-run ends in a failure instead of hanging',
      () async {
        // the handshake goes through, then the devices are moved apart
        final (a, b) = createDevices(
          aCanSendNfc: false,
          aDropsBluetoothAfter: 1,
        );

        final serverRun = start(b, 'passphraseB').catchError((_) {});
        await start(a, 'passphraseA').timeout(const Duration(seconds: 10));
        // the server doesn't keep waiting for the vanished client
        await serverRun.timeout(const Duration(seconds: 10));

        final last = a.events.last;
        expect(last.contactMode.value, DisplayContactMode.done);
        expect(last.result.value!.mode, DisplayMode.failure);
        expect(
          last.result.value!.failureMode,
          DisplayFailureMode.connectionFailed,
        );
        expect(
          a.events.where((e) => e.contactMode.value == .done),
          hasLength(1),
        );
        expect(b.events.last.contactMode.value, DisplayContactMode.done);
        expect(b.events.last.result.value!.mode, DisplayMode.failure);
        expect(
          b.events.last.result.value!.failureMode,
          DisplayFailureMode.connectionFailed,
        );

        await a.manager.close();
        await b.manager.close();
      },
    );

    test(
      'a client does not keep waiting for a server that disconnected',
      () async {
        // the handshake goes through, then the devices are moved apart
        final (a, b) = createDevices(
          aCanSendNfc: false,
          bDropsBluetoothAfterRequests: 1,
        );

        final serverRun = start(b, 'passphraseB');
        await start(a, 'passphraseA').timeout(const Duration(seconds: 10));
        await serverRun.timeout(const Duration(seconds: 10));

        for (final device in [a, b]) {
          final last = device.events.last;
          expect(last.contactMode.value, DisplayContactMode.done);
          expect(last.result.value!.mode, DisplayMode.failure);
          expect(
            last.result.value!.failureMode,
            DisplayFailureMode.connectionFailed,
          );
          expect(
            device.events.where((e) => e.contactMode.value == .done),
            hasLength(1),
          );
        }

        await a.manager.close();
        await b.manager.close();
      },
    );

    test(
      'a client failing on a response tells the server why, right away',
      () async {
        final (a, b) = createDevices(
          aCanSendNfc: false,
          // corrupts the authentication tag of the encrypted responses
          aTamperResponses: (response) => response.length <= 12
              ? response
              : (Uint8List.fromList(response)..[response.length - 1] ^= 0xff),
        );

        final serverRun = start(b, 'passphraseB');
        await start(a, 'passphraseA').timeout(const Duration(seconds: 10));
        await serverRun.timeout(const Duration(seconds: 10));

        expect(a.events.last.result.value!.mode, DisplayMode.failure);
        expect(
          a.events.last.result.value!.failureMode,
          DisplayFailureMode.misformattedMessage,
        );
        expect(b.events.last.result.value!.mode, DisplayMode.error);
        expect(
          b.events.last.result.value!.errorMode,
          DisplayErrorMode.unableToReadContent,
        );

        await a.manager.close();
        await b.manager.close();
      },
    );
  });
}
