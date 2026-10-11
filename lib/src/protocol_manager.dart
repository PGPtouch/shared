import 'dart:async';
import 'dart:collection';
import 'dart:convert';
import 'dart:isolate';
import 'dart:math';
import 'dart:typed_data';

import 'package:collection/collection.dart' show ListEquality;
import 'package:cryptography/cryptography.dart' hide PublicKey, Signature;
import 'package:dart_pg/dart_pg.dart' hide Uint8ListExt;
import 'package:meta/meta.dart';
import 'package:uuid/data.dart';
import 'package:uuid/rng.dart';
import 'package:uuid/uuid.dart';

import '../shared.dart';
import 'common_state.dart';
import 'user_id.dart';

const bleCharacteristicRequest = "b92ab634-78c5-5407-95eb-b0c1c4c26d35";
const bleCharacteristicResponse = "45f2cadc-dd84-5f49-9880-239d6328e79a";

/// Placeholder app error code sent alongside protocol-level error reports.
///
/// The app error code is application-specific per the PGPtouch definition and
/// left uninterpreted by this library; this constant is used as a generic
/// non-zero marker wherever no application context is available.
const _defaultAppErrorCode = 1;

/// Default time to wait between the pages of a multi-page message.
///
/// Much shorter than the overall run timeout, so a stalled transfer is noticed
/// quickly.
const defaultPageTimeout = Duration(seconds: 3);

enum ProtocolRole { clientReceiver, serverSender }

/// Outcome of comparing this device's bootstrap values to the other device's.
@visibleForTesting
enum RoleDecision {
  /// This device waits to be connected to.
  serverSender,

  /// This device connects to the other one.
  clientReceiver,

  /// Both random bytes and nonces are equal; no role can be assigned.
  undecidable,
}

/// Decides the role of this device.
@visibleForTesting
RoleDecision decideRole({
  required int randomSelf,
  required Uint8List nonceSelf,
  required int randomOther,
  required Uint8List nonceOther,
}) {
  if (randomSelf != randomOther) {
    return randomSelf > randomOther
        ? RoleDecision.serverSender
        : RoleDecision.clientReceiver;
  }
  final nonceComparison = nonceSelf.toBigInt().compareTo(nonceOther.toBigInt());
  if (nonceComparison == 0) return RoleDecision.undecidable;
  return nonceComparison > 0
      ? RoleDecision.serverSender
      : RoleDecision.clientReceiver;
}

typedef _NfcInbound = ({Uint8List data, bool loopback});

typedef _SessionKeys = ({SecretKey shared, SecretKey send, SecretKey receive});

/// Buffers the events of a (broadcast) [Stream] from the moment of creation, so
/// that events emitted while the consumer is busy are not lost.
///
/// Multiple streams are merged; the queue is closed once all of them are done.
final class _EventQueue<T> {
  final _buffer = Queue<T>();
  final _subscriptions = <StreamSubscription<T>>[];
  Completer<void>? _waiting;
  bool _closed = false;

  _EventQueue(Iterable<Stream<T>> streams) {
    var open = streams.length;
    for (final stream in streams) {
      _subscriptions.add(
        stream.listen(
          (event) {
            _buffer.add(event);
            _wake();
          },
          onDone: () {
            if (--open > 0) return;
            _closed = true;
            _wake();
          },
        ),
      );
    }
    if (open == 0) _closed = true;
  }

  /// Returns the next event; throws a [StateError] once the stream is closed
  /// (or this queue cancelled) and no buffered events are left.
  Future<T> next() async {
    while (_buffer.isEmpty) {
      if (_closed) throw StateError("No more events.");
      final waiting = _waiting = Completer<void>();
      await waiting.future;
    }
    return _buffer.removeFirst();
  }

  Future<void> cancel() async {
    _closed = true;
    _buffer.clear();
    _wake();
    await Future.wait(_subscriptions.map((s) => s.cancel()));
  }

  void _wake() {
    final waiting = _waiting;
    _waiting = null;
    if (waiting != null && !waiting.isCompleted) waiting.complete();
  }
}

final class ProtocolManager {
  final ProtocolRun run;
  int _nonceCounter = 0;

  ProtocolManager({
    required NfcSenderState nfcSenderState,
    required NfcReceiverState nfcReceiverState,
    required BluetoothSenderState bluetoothSenderState,
    required BluetoothReceiverState bluetoothReceiverState,
  }) : run = ProtocolRun._(
         displayState: DisplayState(),
         nfcSenderState: nfcSenderState,
         nfcReceiverState: nfcReceiverState,
         bluetoothSenderState: bluetoothSenderState,
         bluetoothReceiverState: bluetoothReceiverState,
       );

  /// Closes the protocol manager and releases any associated resources.
  Future<void> close() async => await run.close();

  /// Starts the protocol manager with the given PGP public and private keys.
  ///
  /// The keys are expected to be in the full framed OpenPGP packet-list format.
  /// If the private key is passphrase-encrypted, [privateKeyPassphrase] must be
  /// supplied to unlock it before it can be used for signing.
  ///
  /// You may use [isPrivateKeyEncrypted] to check beforehand, or you wait for
  /// the [ArgumentError] thrown by this method if the private key is encrypted
  /// but no passphrase is provided.
  Future<void> start(
    Uint8List pgpPublicKey,
    Uint8List pgpPrivateKey, {
    String? privateKeyPassphrase,
  }) async {
    // this can be considered to belong to the protocol
    // ignore: invalid_use_of_protected_member
    run.displayState.emit(
      run.displayState.withChanges(null, .initializing, null),
    );

    if (await run.bluetoothSenderState.isConnected()) {
      throw StateError("Bluetooth sender should not be connected at the start");
    }

    final nfcReceiverAvailable = await Future.value(
      run.nfcReceiverState.isAvailable(),
    );
    final bluetoothSenderAvailable = await Future.value(
      run.bluetoothSenderState.isAvailable(),
    );
    if (!nfcReceiverAvailable) {
      throw StateError("NFC receiver must be available at the start");
    } else if (!bluetoothSenderAvailable) {
      throw StateError("Bluetooth must be available at the start");
    }

    final rawPrivateKey = PrivateKey(PacketList.decode(pgpPrivateKey));
    if (rawPrivateKey.isEncrypted && privateKeyPassphrase == null) {
      throw ArgumentError.value(
        pgpPrivateKey,
        "pgpPrivateKey",
        "Private key is encrypted; privateKeyPassphrase is required",
      );
    }
    final privateKey = rawPrivateKey.isEncrypted
        ? await _decryptPrivateKeyInIsolate(
            rawPrivateKey,
            privateKeyPassphrase!,
          )
        : rawPrivateKey;

    // this can be considered to belong to the protocol
    // ignore: invalid_use_of_protected_member
    run.displayState.emit(run.displayState.withChanges(null, .tapOther, null));

    final rng = Random.secure();
    _nonceCounter = 0;
    final random = rng.nextInt(255) + 1;
    final nonce = rng.nextByte(32);
    final usedRequestIds = <int>{};
    Uint8List newRequestId() {
      while (true) {
        final id = rng.nextByte(3);
        if (usedRequestIds.add(id.toInt())) return id;
      }
    }

    final sessionId = Uuid(goptions: GlobalOptions(CryptoRNG())).v4obj();
    late String activeSessionId;

    final x25519 = X25519();
    final ephemeralKeyPair = await x25519.newKeyPair();
    final ephemeralPublicKey = await ephemeralKeyPair.extractPublicKey();

    final nfcSenderAvailable = await Future.value(
      run.nfcSenderState.isAvailable(),
    );
    final capabilities = Capabilities(
      nfc: nfcReceiverAvailable,
      bluetooth: bluetoothSenderAvailable,
      uwb:
          false, // TODO: cf. 1.3, PGPtouch definition; UWB is not yet specified
    ).toMap();

    // SHARED
    SecretKey? ephemeralSecretKey;
    SecretKey? sendKey;
    SecretKey? receiveKey;
    AesGcm? aesGcm;
    // OTHER
    Uint8List? nonceOther;
    Uint8List? ephemeralPublicKeyOther;
    Map<int, bool>? capabilitiesOther;
    Uint8List? pgpPublicKeyOther;
    // OTHER END
    // SHARED END

    Future<Uint8List> encrypt(Uint8List plaintext) async =>
        (await aesGcm!.encrypt(
          plaintext,
          secretKey: sendKey!,
          nonce: (++_nonceCounter).toNBytes(AesGcm.defaultNonceLength),
        )).concatenation();
    Future<Uint8List> decrypt(Uint8List transmitted) async =>
        Uint8List.fromList(
          await aesGcm!.decrypt(
            SecretBox.fromConcatenation(
              transmitted,
              nonceLength: aesGcm!.nonceLength,
              macLength: aesGcm!.macAlgorithm.macLength,
            ),
            secretKey: receiveKey!,
          ),
        );

    // cf. 1.2.1, PGPtouch definition: the client uses the first 32 derived
    // bytes, the server uses the last 32, regardless of message direction
    // Does not touch any shared state, so a peer's key can be validated before
    // this device commits to a role. Throws for keys that make the Diffie-
    // Hellman result predictable (all low-order points yield all zeros).
    Future<_SessionKeys> deriveSessionKeys(
      bool isClient,
      Uint8List sessionIdBytes,
      Uint8List remoteEphemeralPublicKey,
    ) async {
      final shared = await x25519.sharedSecretKey(
        keyPair: ephemeralKeyPair,
        remotePublicKey: SimplePublicKey(
          remoteEphemeralPublicKey,
          type: KeyPairType.x25519,
        ),
      );
      final sharedBytes = await shared.extractBytes();
      var accumulator = 0;
      for (final byte in sharedBytes) {
        accumulator |= byte;
      }
      if (accumulator == 0) {
        shared.destroy();
        throw StateError("Peer X25519 key yields a degenerate shared secret.");
      }

      final derived = await Hkdf(hmac: Hmac.sha512(), outputLength: 64)
          .deriveKey(
            secretKey: shared,
            nonce: sessionIdBytes,
            info: utf8.encode("PGPtouch/V1"),
          );
      final hkdfBytes = await derived.extractBytes();
      final clientKeyBytes = hkdfBytes.sublist(0, 32);
      final serverKeyBytes = hkdfBytes.sublist(32, 64);
      derived.destroy();
      return (
        shared: shared,
        send: SecretKey(isClient ? clientKeyBytes : serverKeyBytes),
        receive: SecretKey(isClient ? serverKeyBytes : clientKeyBytes),
      );
    }

    void installSessionKeys(_SessionKeys keys) {
      ephemeralSecretKey = keys.shared;
      sendKey = keys.send;
      receiveKey = keys.receive;
      aesGcm = AesGcm.with256bits();
    }

    var finished = false;
    ProtocolRole? claimedRole;
    bool claimRole(ProtocolRole candidate) {
      claimedRole ??= candidate;
      return claimedRole == candidate;
    }

    void showDisplay(
      ProtocolRole? deviceRole,
      DisplayContactMode contactMode,
      DisplayResult? result,
    ) {
      if (finished) return;
      // this can be considered to belong to the protocol
      // ignore: invalid_use_of_protected_member
      run.displayState.emit(
        run.displayState.withChanges(
          deviceRole ?? claimedRole,
          contactMode,
          result,
        ),
      );
    }

    void showFailure(DisplayFailureMode mode, {Object? additionalInfo}) =>
        showDisplay(
          null,
          .done,
          DisplayResult(
            mode: .failure,
            errorMode: null,
            failureMode: mode,
            additionalInfo: additionalInfo,
          ),
        );

    final roleDecided = Completer<ProtocolRole>()..future.ignore();
    final serverDone = Completer<void>()..future.ignore();
    var serverSignatureSent = false;
    void abort(String reason) {
      final error = _ProtocolBreakException(reason);
      if (!roleDecided.isCompleted) roleDecided.completeError(error);
      if (!serverDone.isCompleted) serverDone.completeError(error);
    }

    final nfcEvents = _EventQueue<_NfcInbound>([
      run.nfcReceiverState.events.expand(
        (e) => [if (e.received != null) (data: e.received!, loopback: false)],
      ),
      run.nfcSenderState.events.expand(
        (e) => [if (e.received != null) (data: e.received!, loopback: true)],
      ),
    ]);

    // Any NFC activity (our card being selected, a bootstrap read or pushed)
    // proves a physical contact. Until then the BLE server ignores everyone,
    // since the session ID is advertised in the clear.
    var nfcContact = false;
    final nfcContactSubscriptions = [
      run.nfcSenderState.events.listen((_) => nfcContact = true),
      run.nfcReceiverState.events.listen((_) => nfcContact = true),
    ];
    // The bootstrap of the peer that decided this device to be the server. Its
    // BLE handshake has to carry exactly these values.
    NfcBootstrap? expectedPeer;

    try {
      Future<void> runtime() async {
        Future<void> reportUnreadable(
          Uint8List data,
          Future<void> Function(Uint8List) respond,
        ) async {
          if (data.length < 7) return;
          final requestId = data.sublist(4, 7);
          if (requestId.toIntOrNull() == null) return;
          try {
            await respond(
              ErrorReportPayload(
                requestId: requestId,
                appErrorCode: _defaultAppErrorCode,
                errorCode: .error.unableToReadContent,
              ).toBytes(),
            ).timeout(const Duration(seconds: 2));
          } catch (_) {
            // the other device may already be gone
          }
        }

        Future<void> rejectUnreadable(
          Uint8List data,
          Future<void> Function(Uint8List) respond,
        ) async {
          await reportUnreadable(data, respond);
          showFailure(.misformattedMessage);
          abort("Bluetooth negotiation failed due to unreadable content.");
        }

        Future<Payload?> readIncoming(
          Uint8List data,
          Future<void> Function(Uint8List) respond,
        ) async {
          final Payload payload;
          try {
            payload = Payload.fromBytes(data);
          } catch (_) {
            await rejectUnreadable(data, respond);
            return null;
          }
          if (payload is ErrorReportPayload) {
            showDisplay(
              null,
              .done,
              DisplayResult(
                mode: .error,
                errorMode: DisplayErrorMode.fromInt(payload.errorCode.value),
                failureMode: null,
              ),
            );
            abort("Bluetooth negotiation failed due to error report.");
            return null;
          }
          return payload;
        }

        // MARK: Server Runtime (after handshake)
        Future<void> onServerRequest(
          Uint8List data,
          Future<void> Function(Uint8List) respond,
          Object? central,
        ) async {
          if (finished || serverDone.isCompleted) return;
          try {
            final event = await readIncoming(data, respond);
            if (event == null) return;

            if (event is KeyExchangePayload) {
              pgpPublicKeyOther = await decrypt(event.publicPgpKey);
              await executeForPagesOfContent(
                await encrypt(pgpPublicKey),
                (page, pageIndex, pageCount) => respond(
                  KeyExchangePayload(
                    requestId: event.requestId,
                    publicPgpKey: page,
                    pageIndex: pageIndex,
                    pages: pageCount,
                  ).toBytes(),
                ),
              );
            } else if (event is SignatureExchangePayload) {
              final publicKeyOther = pgpPublicKeyOther;
              if (publicKeyOther == null) {
                await rejectUnreadable(data, respond);
                return;
              }
              final signatureOther = await decrypt(event.detachedSignature);

              final fingerprintA = _primaryPublicKeyPacket(pgpPublicKey);
              final fingerprintB = _primaryPublicKeyPacket(publicKeyOther);
              final transcript = _formatTranscript(
                sessionId: activeSessionId,
                nonceA: base64Encode(nonce),
                nonceB: base64Encode(nonceOther!),
                ephemeralA: base64Encode(ephemeralPublicKey.bytes),
                ephemeralB: base64Encode(ephemeralPublicKeyOther!),
                fingerprintA: base64Encode(fingerprintA.fingerprint),
                fingerprintB: base64Encode(fingerprintB.fingerprint),
                capabilitiesA: Capabilities.fromMap(capabilities).toInt(),
                capabilitiesB: Capabilities.fromMap(capabilitiesOther!).toInt(),
                uwb: null, // TODO: cf. 1.3, PGPtouch definition; UWB is not yet specified
              );

              late final Uint8List signature;
              try {
                signature = await _signDetachedInIsolate(
                  transcript,
                  privateKey,
                );
              } catch (e) {
                showFailure(.suppliedKeysFailed, additionalInfo: e);
                abort("Supplied signature failed");
                return;
              }

              await executeForPagesOfContent(
                await encrypt(signature),
                (page, pageIndex, pageCount) => respond(
                  SignatureExchangePayload(
                    requestId: event.requestId,
                    detachedSignature: page,
                    pageIndex: pageIndex,
                    pages: pageCount,
                  ).toBytes(),
                ),
              );
              serverSignatureSent = true;

              final verification = verifyTranscriptSignature(
                transcript,
                publicKeyOther,
                signatureOther,
              );
              if (!verification.isVerified) {
                showFailure(
                  .signatureVerificationFailed,
                  additionalInfo: verification.verificationError,
                );
                abort("Signature verification failed");
                return;
              }

              showDisplay(
                null,
                .done,
                DisplayResult(
                  mode: .success,
                  errorMode: null,
                  failureMode: null,
                  additionalInfo: (
                    fingerprint: fingerprintB.fingerprint,
                    pgpKey: publicKeyOther,
                    userIds: verification.userIds.toSet(),
                  ),
                ),
              );
              if (!serverDone.isCompleted) serverDone.complete();
            } else {
              await rejectUnreadable(data, respond);
            }
          } catch (e) {
            await reportUnreadable(data, respond);
            showFailure(.misformattedMessage, additionalInfo: e);
            abort("Bluetooth negotiation failed: $e");
          }
        }

        // MARK: Server Runtime (handshake)
        // Nothing here is authenticated yet, so everything that is not a
        // plausible handshake of the NFC peer is dropped without consequences
        // for the run; otherwise any BLE device in range could abort it.
        Future<void> onHandshakeRequest(
          Uint8List data,
          Future<void> Function(Uint8List) respond,
          Object? central,
        ) async {
          if (finished || claimedRole != null) return;
          Uint8List? requestId;
          Future<void> reject(PayloadType code) async {
            final id = requestId;
            if (id == null) return;
            try {
              await respond(
                ErrorReportPayload(
                  requestId: id,
                  appErrorCode: _defaultAppErrorCode,
                  errorCode: code,
                ).toBytes(),
              ).timeout(const Duration(seconds: 2));
            } catch (_) {
              // the other device may already be gone
            }
          }

          try {
            final Payload incoming;
            try {
              incoming = Payload.fromBytes(data);
            } catch (_) {
              return;
            }
            if (incoming is! HandshakePayload) return;
            requestId = incoming.requestId;

            if (!incoming.initializerMatchesProtocol()) {
              await reject(.error.headerIncompatible);
              return;
            }
            final expected = expectedPeer;
            if (!nfcContact ||
                (expected != null &&
                    !_handshakeMatchesBootstrap(incoming, expected))) {
              await reject(.error.unableToReadContent);
              return;
            }

            final _SessionKeys keys;
            try {
              keys = await deriveSessionKeys(
                false,
                sessionId.toBytes(),
                incoming.publicX25519Key,
              );
            } catch (_) {
              await reject(.error.unableToReadContent);
              return;
            }

            if (!claimRole(.serverSender)) {
              keys.shared.destroy();
              keys.send.destroy();
              keys.receive.destroy();
              return;
            }
            run.bluetoothReceiverState._bindCentral(central);
            installSessionKeys(keys);
            activeSessionId = sessionId.toFormattedString();
            nonceOther = incoming.nonce;
            ephemeralPublicKeyOther = incoming.publicX25519Key;
            capabilitiesOther = incoming.capabilities;

            run.bluetoothReceiverState._registerReadRequestHandler(
              onServerRequest,
            );
            showDisplay(.serverSender, .holdOther, null);

            await respond(
              HandshakeResponsePayload(requestId: incoming.requestId).toBytes(),
            );

            // TODO: cf. 1.3, PGPtouch definition; UWB is not yet specified

            if (!roleDecided.isCompleted) {
              roleDecided.complete(ProtocolRole.serverSender);
            }
          } catch (e) {
            if (claimedRole != ProtocolRole.serverSender) return;
            showFailure(.connectionFailed, additionalInfo: e);
            abort("Bluetooth negotiation failed: $e");
          }
        }

        // MARK: NFC negotiation
        Future<void> negotiateOverNfc() async {
          try {
            while (!roleDecided.isCompleted) {
              final _NfcInbound event;
              try {
                event = await nfcEvents.next();
                // just exit the loop if the events stream is closed
                // ignore: avoid_catching_errors
              } on StateError {
                if (roleDecided.isCompleted || finished) return;
                throw _ProtocolBreakException(
                  "NFC negotiation failed due to closed events stream.",
                );
              }
              final received = event.data;
              final loopback = event.loopback;
              if (claimedRole == ProtocolRole.serverSender) return;

              final NfcBootstrap payload;
              try {
                payload = NfcBootstrap.fromBytes(received);
              } catch (_) {
                continue;
              }

              if (!payload.initializerMatchesImplementation()) {
                if (loopback) continue;
                showDisplay(
                  null,
                  .done,
                  DisplayResult(
                    mode: .failure,
                    errorMode: null,
                    failureMode: .initializerMismatch,
                    additionalInfo: (
                      expected: protocolInitializerDefaults.version,
                      received: payload.protocolInitializerVersion,
                    ),
                  ),
                );
                throw _ProtocolBreakException(
                  "NFC negotiation failed due to protocol initializer mismatch.",
                );
              }

              final String peerSessionId;
              try {
                peerSessionId = UuidValue.fromByteList(payload.sessionId)
                    .toFormattedString();
              } catch (_) {
                if (loopback) continue;
                showFailure(.misformattedMessage);
                throw _ProtocolBreakException(
                  "NFC negotiation failed due to invalid session ID.",
                );
              }

              if (nfcSenderAvailable) {
                switch (decideRole(
                  randomSelf: random,
                  nonceSelf: nonce,
                  randomOther: payload.random,
                  nonceOther: payload.nonce,
                )) {
                  case RoleDecision.serverSender:
                    expectedPeer = payload;
                    showDisplay(.serverSender, .holdOther, null);
                    await nfcEvents.cancel();
                    await run.nfcReceiverState.dispose();
                    return;
                  case RoleDecision.undecidable:
                    showFailure(.pureLuck);
                    throw _ProtocolBreakException(
                      "NFC negotiation failed due to random/nonce comparison. "
                      "(Chances for this are 2^-264; extremely unlikely)",
                    );
                  case RoleDecision.clientReceiver:
                    break;
                }
              }

              final _SessionKeys keys;
              try {
                keys = await deriveSessionKeys(
                  true,
                  payload.sessionId,
                  payload.publicX25519Key,
                );
              } catch (_) {
                if (loopback) continue;
                showFailure(.misformattedMessage);
                throw _ProtocolBreakException(
                  "NFC negotiation failed due to an invalid X25519 key.",
                );
              }

              if (!claimRole(.clientReceiver)) {
                keys.shared.destroy();
                keys.send.destroy();
                keys.receive.destroy();
                return;
              }
              activeSessionId = peerSessionId;
              showDisplay(.clientReceiver, .holdOther, null);

              await nfcEvents.cancel();
              await run.nfcReceiverState.dispose();

              try {
                run.bluetoothSenderState.resetConnectionLoss();
                if (!await run.bluetoothSenderState.connect(activeSessionId)) {
                  throw Exception();
                }
              } catch (_) {
                showFailure(.connectionFailed);
                throw _ProtocolBreakException(
                  "NFC negotiation failed due to connection failure.",
                );
              }

              nonceOther = payload.nonce;
              ephemeralPublicKeyOther = payload.publicX25519Key;
              capabilitiesOther = payload.capabilities;
              installSessionKeys(keys);

              if (!roleDecided.isCompleted) {
                roleDecided.complete(ProtocolRole.clientReceiver);
              }
              return;
            }
          } catch (e) {
            if (!roleDecided.isCompleted) roleDecided.completeError(e);
          }
        }

        run.bluetoothReceiverState._registerReadRequestHandler(
          onHandshakeRequest,
        );
        run.bluetoothReceiverState._registerConnectionLossHandler((reason) {
          if (finished ||
              claimedRole != ProtocolRole.serverSender ||
              serverDone.isCompleted ||
              serverSignatureSent) {
            return;
          }
          showFailure(.connectionFailed);
          abort("Bluetooth negotiation failed: $reason");
        });
        await (run.bluetoothReceiverState..data = sessionId.toFormattedString())
            .start();
        if (nfcSenderAvailable) {
          await (run.nfcSenderState
                ..data = NfcBootstrap(
                  random: random,
                  sessionId: sessionId.toBytes(validate: true),
                  capabilities: capabilities,
                  nonce: nonce,
                  publicX25519Key: Uint8List.fromList(ephemeralPublicKey.bytes),
                ))
              .start();
        }
        await run.nfcReceiverState.start();

        // errors are routed to roleDecided inside
        // ignore: unawaited_futures
        negotiateOverNfc();
        final role = await roleDecided.future;

        await nfcEvents.cancel();
        await run.nfcSenderState.dispose();
        await run.nfcReceiverState.dispose();
        if (role == ProtocolRole.clientReceiver) {
          // MARK: Client Runtime
          if (!serverDone.isCompleted) serverDone.complete();
          run.bluetoothReceiverState._unregisterReadRequestHandler();
          await run.bluetoothReceiverState.dispose();

          void ensureActive() {
            if (finished) {
              throw _ProtocolBreakException("Protocol run already finished.");
            }
          }

          Future<void> reportError(PayloadType code) async {
            try {
              await run.bluetoothSenderState
                  .send(
                    ErrorReportPayload(
                      requestId: newRequestId(),
                      appErrorCode: _defaultAppErrorCode,
                      errorCode: code,
                    ).toBytes(),
                  )
                  .timeout(const Duration(seconds: 2));
            } catch (_) {
              // the other device may already be gone
            }
          }

          Future<T> receiveResponse<T extends Payload>(
            Uint8List requestId,
            String stage,
          ) async {
            final raw = await run.bluetoothSenderState.receiveRequestIdResponse(
              requestId.toInt(),
            );
            ensureActive();
            final Payload response;
            try {
              response = Payload.fromBytes(raw);
            } catch (_) {
              showFailure(.misformattedMessage);
              await reportError(.error.unableToReadContent);
              throw _ProtocolBreakException(
                "Bluetooth $stage failed due to misformatted message.",
              );
            }
            if (response is ErrorReportPayload) {
              showDisplay(
                null,
                .done,
                DisplayResult(
                  mode: .error,
                  errorMode: DisplayErrorMode.fromInt(response.errorCode.value),
                  failureMode: null,
                ),
              );
              throw _ProtocolBreakException(
                "Bluetooth $stage failed due to error report.",
              );
            }
            if (response is! T) {
              showFailure(.misformattedMessage);
              await reportError(.error.unableToReadContent);
              throw _ProtocolBreakException(
                "Bluetooth $stage failed due to unexpected message.",
              );
            }
            return response;
          }

          Future<Uint8List> decryptOrFail(Uint8List transmitted) async {
            try {
              return await decrypt(transmitted);
            } catch (_) {
              showFailure(.misformattedMessage);
              await reportError(.error.unableToReadContent);
              throw _ProtocolBreakException(
                "Bluetooth message could not be decrypted.",
              );
            }
          }

          final handshakeRequestId = newRequestId();
          await run.bluetoothSenderState.send(
            HandshakePayload(
              requestId: handshakeRequestId,
              capabilities: capabilities,
              nonce: nonce,
              publicX25519Key: Uint8List.fromList(ephemeralPublicKey.bytes),
            ).toBytes(),
          );
          await receiveResponse<HandshakeResponsePayload>(
            handshakeRequestId,
            "handshake",
          );

          final keyExchangeRequestId = newRequestId();
          await executeForPagesOfContent(
            await encrypt(pgpPublicKey),
            (page, pageIndex, pageCount) async =>
                await run.bluetoothSenderState.send(
                  KeyExchangePayload(
                    requestId: keyExchangeRequestId,
                    publicPgpKey: page,
                    pageIndex: pageIndex,
                    pages: pageCount,
                  ).toBytes(),
                ),
          );
          final keyExchangeResponse = await receiveResponse<KeyExchangePayload>(
            keyExchangeRequestId,
            "key exchange",
          );
          pgpPublicKeyOther = await decryptOrFail(
            keyExchangeResponse.publicPgpKey,
          );

          final fingerprintA = _primaryPublicKeyPacket(pgpPublicKeyOther!);
          final fingerprintB = _primaryPublicKeyPacket(pgpPublicKey);
          final transcript = _formatTranscript(
            sessionId: activeSessionId,
            nonceA: base64Encode(nonceOther!),
            nonceB: base64Encode(nonce),
            ephemeralA: base64Encode(ephemeralPublicKeyOther!),
            ephemeralB: base64Encode(ephemeralPublicKey.bytes),
            fingerprintA: base64Encode(fingerprintA.fingerprint),
            fingerprintB: base64Encode(fingerprintB.fingerprint),
            capabilitiesA: Capabilities.fromMap(capabilitiesOther!).toInt(),
            capabilitiesB: Capabilities.fromMap(capabilities).toInt(),
            uwb: null, // TODO: cf. 1.3, PGPtouch definition; UWB is not yet specified
          );
          final signature = await () async {
            try {
              return await _signDetachedInIsolate(transcript, privateKey);
            } catch (e) {
              showFailure(.suppliedKeysFailed, additionalInfo: e);
              throw _ProtocolBreakException("Supplied signature failed");
            }
          }();

          final signatureExchangeRequestId = newRequestId();
          await executeForPagesOfContent(
            await encrypt(signature),
            (page, pageIndex, pageCount) async =>
                await run.bluetoothSenderState.send(
                  SignatureExchangePayload(
                    requestId: signatureExchangeRequestId,
                    detachedSignature: page,
                    pageIndex: pageIndex,
                    pages: pageCount,
                  ).toBytes(),
                ),
          );
          final signatureExchangeResponse =
              await receiveResponse<SignatureExchangePayload>(
                signatureExchangeRequestId,
                "signature exchange",
              );

          final verification = verifyTranscriptSignature(
            transcript,
            pgpPublicKeyOther!,
            await decryptOrFail(signatureExchangeResponse.detachedSignature),
          );
          if (!verification.isVerified) {
            showFailure(
              .signatureVerificationFailed,
              additionalInfo: verification.verificationError,
            );
            await reportError(.error.unableToReadContent);
            throw _ProtocolBreakException(
              "Bluetooth signature verification failed.",
            );
          }

          showDisplay(
            null,
            .done,
            DisplayResult(
              mode: .success,
              errorMode: null,
              failureMode: null,
              additionalInfo: (
                fingerprint: fingerprintA.fingerprint,
                pgpKey: pgpPublicKeyOther!,
                userIds: verification.userIds.toSet(),
              ),
            ),
          );
        } else if (role == ProtocolRole.serverSender) {
          await run.bluetoothSenderState.dispose();
          await serverDone.future;
          // behavior defined above
        }
      }

      await runtime().timeout(
        const Duration(seconds: 20),
        onTimeout: () {
          showFailure(.timeout);
          throw _ProtocolBreakException(
            "Protocol run timed out after 20 seconds.",
          );
        },
      );
    } on _ProtocolBreakException catch (_) {
      // error should've been handled by a previous DisplayState update
    } catch (e) {
      // e.g. the Bluetooth connection dropping because the devices were moved
      // apart too early; must never leave the display in a pending state. the
      // error is handed to the app through DisplayResult.additionalInfo.
      showFailure(.connectionFailed, additionalInfo: e);
    } finally {
      finished = true;
      run.bluetoothReceiverState._unregisterReadRequestHandler();
      run.bluetoothReceiverState._unregisterConnectionLossHandler();
      await nfcEvents.cancel();
      for (final subscription in nfcContactSubscriptions) {
        await subscription.cancel();
      }

      nonce.destroy();
      ephemeralKeyPair.destroy();
      ephemeralSecretKey?.destroy();
      sendKey?.destroy();
      receiveKey?.destroy();

      nonceOther?.destroy();
      ephemeralPublicKeyOther?.destroy();

      await run.nfcSenderState.dispose();
      await run.nfcReceiverState.dispose();
      try {
        if (await run.bluetoothSenderState.isConnected()) {
          await run.bluetoothSenderState.disconnect();
        }
      } catch (_) {
        // best-effort; the connection might already be gone
      }
      await run.bluetoothSenderState.dispose();
      await run.bluetoothReceiverState.dispose();
    }
  }

  String _formatTranscript({
    required String sessionId,
    required String nonceA,
    required String nonceB,
    required String ephemeralA,
    required String ephemeralB,
    required String fingerprintA,
    required String fingerprintB,
    required int capabilitiesA,
    required int capabilitiesB,
    required Object? uwb,
  }) {
    final data = {
      "protocol": "PGPtouch",
      "version": 1,
      "sessionId": sessionId,
      "nonceA": nonceA,
      "nonceB": nonceB,
      "ephemeralA": ephemeralA,
      "ephemeralB": ephemeralB,
      "fingerprintA": fingerprintA,
      "fingerprintB": fingerprintB,
      "capabilitiesA": capabilitiesA,
      "capabilitiesB": capabilitiesB,
      "uwb": uwb,
    };
    var jsonString = jsonEncode(data);
    while (jsonString.contains(RegExp(r"\s"))) {
      jsonString = jsonString.replaceAll(RegExp(r"\s"), "");
    }
    while (jsonString.contains(RegExp(r"\n"))) {
      jsonString = jsonString.replaceAll(RegExp(r"\n"), "");
    }
    return jsonString;
  }
}

/// Exception used to completely break the protocol flow in case of a critical
/// protocol failure.
///
/// Before throwing this, ensure that a DisplayState update has been made to
/// inform the application about the protocol failure.
final class _ProtocolBreakException implements Exception {
  final dynamic message;
  const _ProtocolBreakException([this.message]);

  @override
  String toString() {
    final Object? message = this.message;
    if (message == null) return "_ProtocolBreakException";
    return "_ProtocolBreakException: $message";
  }
}

final class ProtocolRun {
  final DisplayState displayState;

  final NfcSenderState nfcSenderState;
  final NfcReceiverState nfcReceiverState;
  final BluetoothSenderState bluetoothSenderState;
  final BluetoothReceiverState bluetoothReceiverState;

  ProtocolRun._({
    required this.displayState,
    required this.nfcSenderState,
    required this.nfcReceiverState,
    required this.bluetoothSenderState,
    required this.bluetoothReceiverState,
  });

  Future<void> close() async {
    await displayState.dispose();
    await nfcSenderState.dispose();
    await nfcReceiverState.dispose();
    await bluetoothSenderState.dispose();
    await bluetoothReceiverState.dispose();
  }
}

final class DisplayState extends CommonState<DisplayState, DisplayEvent> {
  bool _disposed = false;

  @override
  @protected
  void emit(DisplayEvent event) {
    if (_disposed) return;
    final isDone = lastEvent?.contactMode.value == DisplayContactMode.done;
    if (isDone && event.contactMode.value != DisplayContactMode.initializing) {
      return;
    }
    super.emit(event);
  }

  @override
  Future<void> dispose() {
    _disposed = true;
    return super.dispose();
  }

  DisplayEvent withChanges(
    ProtocolRole? deviceRole,
    DisplayContactMode contactMode,
    DisplayResult? result,
  ) =>
      lastEvent?.withChanges(deviceRole, contactMode, result) ??
      DisplayEvent(
        deviceRole: ValueChangedContainer._initial(deviceRole),
        contactMode: ValueChangedContainer._initial(contactMode),
        result: ValueChangedContainer._initial(result),
      );
}

final class DisplayEvent extends Event<DisplayState> {
  final ValueChangedContainer<ProtocolRole?> deviceRole;
  final ValueChangedContainer<DisplayContactMode> contactMode;
  final ValueChangedContainer<DisplayResult?> result;

  DisplayEvent({
    required this.deviceRole,
    required this.contactMode,
    required this.result,
  });

  DisplayEvent withChanges(
    ProtocolRole? deviceRole,
    DisplayContactMode contactMode,
    DisplayResult? result,
  ) => DisplayEvent(
    deviceRole: ValueChangedContainer._fromLast(
      deviceRole,
      this.deviceRole.value,
    ),
    contactMode: ValueChangedContainer._fromLast(
      contactMode,
      this.contactMode.value,
    ),
    result: ValueChangedContainer._fromLast(result, this.result.value),
  );
}

enum DisplayContactMode {
  /// App should display that the protocol is currently initializing.
  initializing,

  /// App should display the need to tap the other device to the user's.
  tapOther,

  /// App should display the need to actively keep holding the user's device to
  /// the other device.
  holdOther,

  /// App should display that the action is done.
  ///
  /// See [DisplayEvent.result] for the outcome of the verification.
  done,
}

enum DisplayMode {
  /// The operation was successful.
  ///
  /// Indicates that the operation was successful. If so,
  /// [DisplayResult.additionalInfo] will hold the following information:
  /// `({Uint8List fingerprint, Uint8List pgpKey, Set<String> userIds})`
  success,

  /// Error transmitted by the other device.
  error,

  /// Failure due to an expected condition, for example a signature error,
  /// format mismatch or other expected conditions.
  failure,
}

enum DisplayErrorMode {
  /// The headers (most likely the initializers) have been determined to be
  /// incompatible.
  ///
  /// This should've already been caught in the initialization phase of this
  /// device. It might be worth reporting a bug.
  headerIncompatible,

  /// A page this client was supposed to send was not sent in time.
  pageTimeout,

  /// The content of the message seems to be unreadable or corrupted.
  unableToReadContent;

  static DisplayErrorMode? fromInt(int value) => switch (value) {
    1 => headerIncompatible,
    2 => pageTimeout,
    3 => unableToReadContent,
    _ => null,
  };
}

enum DisplayFailureMode {
  /// The protocol manager was unable to parse parts of the request.
  misformattedMessage,

  /// There's been a mismatch between the expected initializer for this
  /// implementation of the protocol to the data received.
  ///
  /// This usually means either this or the other device is outdated. If this is
  /// set, [DisplayResult.additionalInfo] contains a Record of the versions
  /// using this format: `({int expected, int received})`
  initializerMismatch,

  /// This means that the random byte as well as the nonce are equally generated
  /// by both this device and the other.
  ///
  /// In this case, the protocol is unable to determine the correct roles, thus
  /// the run has to be cancelled. The chances for this are extremely low,
  /// $2^-264$ to be exact.
  pureLuck,

  /// The connection attempt to the other device has failed.
  ///
  /// This usually indicates a network or hardware issue preventing the
  /// connection.
  connectionFailed,

  /// The signature on this device could not be generated correctly.
  ///
  /// If this is set, [DisplayResult.additionalInfo] contains the underlying
  /// error thrown while signing.
  suppliedKeysFailed,

  /// The verification of the signature of the other device failed.
  ///
  /// The transmitted signature couldn't be verified successfully, indicating a
  /// potential tampering or corruption of the transmitted signature.
  ///
  /// If this is set, [DisplayResult.additionalInfo] may contain additional
  /// information about the issue.
  signatureVerificationFailed,

  /// The protocol run did not complete within the allotted time.
  ///
  /// Unlike [connectionFailed], this doesn't necessarily indicate a network or
  /// hardware issue; it means the overall run simply took too long, e.g.
  /// because one of the devices stalled somewhere along the way.
  timeout,
}

final class DisplayResult {
  final DisplayMode mode;

  final DisplayErrorMode? errorMode;
  final DisplayFailureMode? failureMode;

  final dynamic additionalInfo;

  DisplayResult({
    required this.mode,
    required this.errorMode,
    required this.failureMode,
    this.additionalInfo,
  });
}

final class ValueChangedContainer<E extends Object?> {
  final E value;

  /// Indicates whether the value has changed since the last sent event.
  final bool hasChanged;

  ValueChangedContainer._({required this.value, required this.hasChanged});
  ValueChangedContainer._initial(E value)
    : this._(value: value, hasChanged: true);
  factory ValueChangedContainer._fromLast(E value, E? lastValue) {
    return ValueChangedContainer._(
      value: value,
      hasChanged: value != lastValue,
    );
  }
}

// MARK: Application Code

abstract base class NfcSenderState
    extends CommonState<NfcSenderState, NfcSenderEvent>
    with
        StartableCommonState<NfcSenderState, NfcSenderEvent>,
        CommonStateWithData<NfcSenderState, NfcSenderEvent, NfcBootstrap>,
        CommonStateWithAvailabilityCheck<NfcSenderState, NfcSenderEvent> {}

final class NfcSenderEvent extends Event<NfcSenderState> {
  /// A bootstrap the other device pushed to this one.
  final Uint8List? received;
  NfcSenderEvent({this.received});

  /// This device's card was selected by a reader, i.e. a physical contact
  /// happened. Implementations must emit this on every select; the protocol
  /// manager only accepts a BLE handshake after any NFC activity.
  NfcSenderEvent.selected() : received = null;
}

abstract base class NfcReceiverState
    extends CommonState<NfcReceiverState, NfcReceiverEvent>
    with
        StartableCommonState<NfcReceiverState, NfcReceiverEvent>,
        CommonStateWithAvailabilityCheck<NfcReceiverState, NfcReceiverEvent> {}

final class NfcReceiverEvent extends Event<NfcReceiverState> {
  final Uint8List? received;
  NfcReceiverEvent({required this.received});
}

abstract base class BluetoothSenderState
    extends CommonState<BluetoothSenderState, BluetoothSenderEvent>
    with
        CommonStateWithAvailabilityCheck<
          BluetoothSenderState,
          BluetoothSenderEvent
        > {
  Future<bool> connect(String sessionId);
  Future<void> disconnect();
  Future<bool> isConnected();

  Future<void> send(Uint8List data);

  /// Checks whether Bluetooth is currently available.
  ///
  /// If this returns `true`, both [BluetoothSenderState] and
  /// [BluetoothReceiverState] are assumed to be available.
  @override
  FutureOr<bool> isAvailable();

  final _pageBuffer = <int, List<Payload?>>{};
  final _responseCompleters = <int, Completer<Uint8List>>{};
  final _pageTimers = <int, Timer>{};

  /// How long to wait for the next page of a multi-page response.
  ///
  /// If this timeout is reached, the response gets dropped and reported to the
  /// remote device with [ErrorPayloadType.pageTimeout].
  @protected
  Duration get pageTimeout => defaultPageTimeout;

  Completer<Uint8List> _completerFor(int requestId) =>
      _responseCompleters.putIfAbsent(requestId, Completer<Uint8List>.new);

  void _armPageTimeout(int requestId) {
    _pageTimers[requestId]?.cancel();
    _pageTimers[requestId] = Timer(pageTimeout, () async {
      _pageTimers.remove(requestId);
      _pageBuffer.remove(requestId);
      final completer = _completerFor(requestId);
      if (!completer.isCompleted) {
        completer.future.ignore();
        completer.completeError(
          TimeoutException("Next page of a response not received in time."),
        );
      }
      try {
        await send(
          ErrorReportPayload(
            requestId: requestId.toNBytes(3),
            appErrorCode: _defaultAppErrorCode,
            errorCode: .error.pageTimeout,
          ).toBytes(),
        );
      } catch (_) {
        // the other device may already be gone
      }
    });
  }

  /// Handles a notification received from the remote Bluetooth device on
  /// [bleCharacteristicResponse].
  ///
  /// This must be called by the stream listener whenever a
  /// notification/response arrives. Multi-page responses are reassembled
  /// automatically before completing the corresponding
  /// [receiveRequestIdResponse] call.
  @protected
  Future<void> notificationHandler(Uint8List data) async {
    final entry = protocolStatesMultiPageHandler(_pageBuffer, data).entries;
    if (entry.isEmpty) return;
    if (!entry.first.value) {
      _armPageTimeout(entry.first.key);
      return;
    }
    _pageTimers.remove(entry.first.key)?.cancel();
    final pages = _pageBuffer.remove(entry.first.key)!.map((e) => e!.toBytes());

    final stitchedData = Uint8List.fromList([
      ...pages.first.take(12),
      ...pages.expand((e) => e.skip(12)),
    ]);
    final stitchedDataContentLength = (stitchedData.length - 12).toNBytes(2);
    stitchedData.setRange(10, 12, stitchedDataContentLength);

    final completer = _completerFor(entry.first.key);
    if (!completer.isCompleted) completer.complete(stitchedData);
  }

  /// Receives a response for the given request ID.
  ///
  /// Waits for the response corresponding to the given request ID, which is
  /// reassembled across pages by [notificationHandler] if necessary.
  ///
  /// Throws a [StateError] if this state is disposed or the connection is lost
  /// (see [peripheralDisconnected]) while waiting.
  @nonVirtual
  Future<Uint8List> receiveRequestIdResponse(int requestId) async {
    final completer = _completerFor(requestId);
    if (_connectionLost && !completer.isCompleted) _failConnectionLost();
    try {
      return await completer.future;
    } finally {
      _responseCompleters.remove(requestId);
    }
  }

  bool _connectionLost = false;

  /// Called by the protocol manager before connecting; a new connection starts
  /// without a loss.
  @nonVirtual
  @visibleForTesting
  void resetConnectionLoss() => _connectionLost = false;

  void _failConnectionLost() {
    for (final completer in _responseCompleters.values) {
      if (completer.isCompleted) continue;
      completer.future.ignore();
      completer.completeError(
        StateError("The other device disconnected before a response arrived."),
      );
    }
  }

  /// Must be called when the remote Bluetooth device (the server) disconnects
  /// or the connection is lost.
  ///
  /// Responses that are still awaited fail right away instead of running into
  /// the timeout of the whole run. Responses that already arrived stay valid.
  @protected
  void peripheralDisconnected() {
    _connectionLost = true;
    _failConnectionLost();
  }

  @override
  Future<void> dispose() async {
    final pending = _responseCompleters.values.toList();
    _responseCompleters.clear();
    _pageBuffer.clear();
    for (final timer in _pageTimers.values) {
      timer.cancel();
    }
    _pageTimers.clear();
    for (final completer in pending) {
      if (completer.isCompleted) continue;
      completer.future.ignore();
      completer.completeError(
        StateError("Bluetooth sender disposed before a response arrived."),
      );
    }
    await super.dispose();
  }
}

final class BluetoothSenderEvent extends Event<BluetoothSenderState> {}

typedef BluetoothReceiverReadRequestHandler = FutureOr<void> Function(
  Uint8List data,
  Future<void> Function(Uint8List) sendResponseWriteRequest,
  Object? central,
);

/// The state class for the Bluetooth receiver.
///
/// Handles read requests from another Bluetooth device. It must manage BLE
/// Peripheral service creation and management in the [start] method with the
/// service id in [data] and the characteristic ids defined by
/// [bleCharacteristicRequest] and [bleCharacteristicResponse].
///
/// The state must manage BLE Peripheral service lifecycle and handle write
/// requests from the remote device accordingly. It must first affirm the write
/// request to the remote device, then call and await the [readRequestHandler]
/// method's execution.
abstract base class BluetoothReceiverState
    extends CommonState<BluetoothReceiverState, BluetoothReceiverEvent>
    with
        StartableCommonState<BluetoothReceiverState, BluetoothReceiverEvent>,
        CommonStateWithData<
          BluetoothReceiverState,
          BluetoothReceiverEvent,
          String
        > {
  BluetoothReceiverReadRequestHandler? _readRequestHandler;
  @nonVirtual
  void _registerReadRequestHandler(
    BluetoothReceiverReadRequestHandler handler,
  ) => _readRequestHandler = handler;
  @nonVirtual
  void _unregisterReadRequestHandler() => _readRequestHandler = null;

  void Function(String reason)? _connectionLossHandler;
  @nonVirtual
  void _registerConnectionLossHandler(void Function(String reason) handler) =>
      _connectionLossHandler = handler;
  @nonVirtual
  void _unregisterConnectionLossHandler() => _connectionLossHandler = null;

  bool _centralBound = false;
  Object? _boundCentral;

  /// Once the protocol manager accepted a handshake, only this central may
  /// talk to it; requests and disconnects of other centrals are ignored.
  @nonVirtual
  void _bindCentral(Object? central) {
    _centralBound = true;
    _boundCentral = central;
  }

  bool _isForeignCentral(Object? central) =>
      _centralBound && central != _boundCentral;

  final _pageBuffer = <int, List<Payload?>>{};
  final _pageTimers = <int, Timer>{};

  /// How long to wait for the next page of a multi-page request.
  ///
  /// If this timeout is reached, the request gets dropped and reported to the
  /// remote device with [ErrorPayloadType.pageTimeout].
  @protected
  Duration get pageTimeout => defaultPageTimeout;

  /// Must be called when the remote Bluetooth device (the client) disconnects.
  ///
  /// This lets an unfinished run fail right away instead of waiting for a
  /// request that will never arrive. Pass the identifier of the disconnected
  /// [central] (the same one given to [readRequestHandler]) so that the
  /// disconnect of an unrelated device is not mistaken for the loss of the
  /// client.
  @protected
  void centralDisconnected({Object? central}) {
    if (_isForeignCentral(central)) return;
    _connectionLossHandler?.call("The other device disconnected.");
  }

  void _armPageTimeout(
    int requestId,
    Future<void> Function(Uint8List) sendResponseWriteRequest,
  ) {
    _pageTimers[requestId]?.cancel();
    _pageTimers[requestId] = Timer(pageTimeout, () async {
      _pageTimers.remove(requestId);
      _pageBuffer.remove(requestId);
      try {
        await sendResponseWriteRequest(
          ErrorReportPayload(
            requestId: requestId.toNBytes(3),
            appErrorCode: _defaultAppErrorCode,
            errorCode: .error.pageTimeout,
          ).toBytes(),
        );
      } catch (_) {
        // the other device may already be gone
      }
      _connectionLossHandler?.call(
        "Next page of a request not received in time.",
      );
    });
  }

  @override
  Future<void> dispose() async {
    _readRequestHandler = null;
    _connectionLossHandler = null;
    _centralBound = false;
    _boundCentral = null;
    _pageBuffer.clear();
    for (final timer in _pageTimers.values) {
      timer.cancel();
    }
    _pageTimers.clear();
    await super.dispose();
  }

  /// Handles a read request from the remote Bluetooth device.
  ///
  /// This method should be called when a read request is received from the
  /// other device. Once it has finished executing, continue as described in the
  /// [BluetoothReceiverState] documentation.
  ///
  /// [sendResponseWriteRequest] should send a new read request to the remote
  /// Bluetooth device with the passed data.
  ///
  /// [central] identifies the sending remote device, if the platform can tell
  /// devices apart. Once the protocol manager bound itself to a central, any
  /// other one is ignored.
  ///
  /// Unterstützung für mehrseitige Protokoll-Requests ist eingebaut.
  @protected
  Future<void> readRequestHandler(
    Uint8List data,
    Future<void> Function(Uint8List) sendResponseWriteRequest, {
    Object? central,
  }) async {
    if (_isForeignCentral(central)) return;
    final entry = protocolStatesMultiPageHandler(_pageBuffer, data).entries;
    if (entry.isEmpty) return;
    if (!entry.first.value) {
      _armPageTimeout(entry.first.key, sendResponseWriteRequest);
      return;
    }
    _pageTimers.remove(entry.first.key)?.cancel();
    final buffer = _pageBuffer
        .remove(entry.first.key)!
        .map((e) => e!.toBytes())
        .toList();
    final stitchedData = Uint8List.fromList([
      ...buffer.first.take(12),
      ...buffer.expand((e) => e.skip(12)),
    ]);
    final stitchedDataContentLength = (stitchedData.length - 12).toNBytes(2);
    stitchedData.setRange(10, 12, stitchedDataContentLength);
    // the buffer entry is released before the handler runs, so a failing
    // handler can't leave stale pages behind for a retried request ID
    await Future.value(
      _readRequestHandler?.call(
        stitchedData,
        sendResponseWriteRequest,
        central,
      ),
    );
  }
}

final class BluetoothReceiverEvent extends Event<BluetoothReceiverState> {
  final Uint8List? received;
  BluetoothReceiverEvent({required this.received});
}

/// Helper function to process multi-page protocol requests.
///
/// It takes a [pageBuffer] that maps request IDs to lists of payload pages, and
/// the incoming [data] as a [Uint8List].
///
/// The returned map has the request ID of the page in [data] as the key, and a
/// boolean indicating whether all pages for that request ID have been received
/// as value.
Map<int, bool> protocolStatesMultiPageHandler(
  Map<int, List<Payload?>> pageBuffer,
  Uint8List data,
) {
  try {
    final payload = Payload.fromBytes(data);
    final requestId = payload.requestId.toInt();
    final existing = pageBuffer[requestId];
    if (existing != null && existing.length != payload.pages) {
      // inconsistent page count; drop the corrupted request
      pageBuffer.remove(requestId);
      return {};
    }
    if (existing == null) {
      pageBuffer[requestId] = List.generate(
        payload.pages,
        (_) => null,
        growable: false,
      );
    }
    pageBuffer[requestId]![payload.pageIndex - 1] = payload;
    return {
      requestId: pageBuffer[requestId]!.every((element) => element != null),
    };
  } catch (_) {
    return {};
  }
}

/// Executes a callback for each page of the given content.
///
/// The [content] is split into pages of size 500 bytes. The [callback] is
/// called for each page with the page data, the 1-based page index, and the
/// total page count.
Future<void> executeForPagesOfContent(
  Uint8List content,
  FutureOr<void> Function(Uint8List page, int pageIndex, int pageCount)
  callback,
) async {
  final pageSize = 500;
  final pageCount = content.isEmpty ? 1 : (content.length / pageSize).ceil();
  for (var i = 0; i < pageCount; i++) {
    final chunk = content.sublist(
      i * pageSize,
      (i + 1) * pageSize > content.length ? content.length : (i + 1) * pageSize,
    );
    await Future.value(callback.call(chunk, i + 1, pageCount));
  }
}

/// Checks if the handshake of the BLE client carries the values of the
/// bootstrap that was exchanged over NFC.
bool _handshakeMatchesBootstrap(
  HandshakePayload handshake,
  NfcBootstrap bootstrap,
) =>
    const ListEquality<int>().equals(handshake.nonce, bootstrap.nonce) &&
    const ListEquality<int>().equals(
      handshake.publicX25519Key,
      bootstrap.publicX25519Key,
    ) &&
    Capabilities.fromMap(handshake.capabilities).toInt() ==
        Capabilities.fromMap(bootstrap.capabilities).toInt();

/// Checks if the given PGP private key is encrypted.
bool isPrivateKeyEncrypted(Uint8List pgpPrivateKey) =>
    PrivateKey(PacketList.decode(pgpPrivateKey)).isEncrypted;

Future<PrivateKey> _decryptPrivateKeyInIsolate(
  PrivateKey key,
  String passphrase,
) => Isolate.run(() => key.decrypt(passphrase) as PrivateKey);

Future<Uint8List> _signDetachedInIsolate(String transcript, PrivateKey key) =>
    Isolate.run(
      () => Uint8List.fromList(
        OpenPGP.signDetachedCleartext(transcript, [key]).packetList.encode(),
      ),
    );

PublicKeyPacket _primaryPublicKeyPacket(Uint8List framedPacketListBytes) =>
    PacketList.decode(framedPacketListBytes).packets
        .whereType<PublicKeyPacket>()
        .first;

typedef TranscriptVerification = ({
  bool isVerified,
  String verificationError,
  Iterable<String> userIds,
});

/// Verifies the detached [signatureBytes] over [transcript] using
/// [publicKeyBytes].
///
/// Unlike [CleartextMessage.verifyDetached], this deliberately ignores the
/// signature creation time: the transcript already binds the signature to this
/// session through its nonces and ephemeral keys, while the wall clocks of two
/// independent devices are not synchronized, so a signer whose clock runs ahead
/// of the verifier would otherwise be rejected with "Signature is expired.".
@visibleForTesting
TranscriptVerification verifyTranscriptSignature(
  String transcript,
  Uint8List publicKeyBytes,
  Uint8List signatureBytes,
) {
  bool bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  final publicKey = PublicKey(PacketList.decode(publicKeyBytes));
  final keyPacket = publicKey.keyPacket;
  final userIds = publicKey.users
      .where((user) => user.userID.isNotEmpty)
      .map((user) => user.userID)
      .toList();
  TranscriptVerification failure(String error) =>
      (isVerified: false, verificationError: error, userIds: userIds);

  for (final id in userIds) {
    try {
      UserId.parse(id);
    } catch (e) {
      return failure(e.toString());
    }
  }

  final signature = PacketList.decode(signatureBytes).packets
      .whereType<SignaturePacket>()
      .where((packet) => bytesEqual(packet.issuerKeyID, keyPacket.keyID))
      .firstOrNull;
  if (signature == null) {
    return failure("No signature issued by the given public key.");
  }
  if (signature.keyAlgorithm != keyPacket.keyAlgorithm) {
    return failure(
      "Key algorithm used to sign does not match issuer key algorithm.",
    );
  }

  final message = Uint8List.fromList([
    ...signature.salt,
    ...LiteralDataPacket.fromText(transcript).signBytes,
    ...signature.signatureData,
    signature.version,
    0xff,
    ...(ByteData(
      4,
    )..setUint32(0, signature.signatureData.length)).buffer.asUint8List(),
  ]);
  final hash = Helper.hashDigest(message, signature.hashAlgorithm);
  if (signature.signedHashValue[0] != hash[0] ||
      signature.signedHashValue[1] != hash[1]) {
    return failure('Assertion failed: "Signed digest did not match!"');
  }

  final dynamic keyMaterial = keyPacket.keyMaterial;
  try {
    final isVerified = keyMaterial.verify(
      message,
      signature.hashAlgorithm,
      signature.signature,
    ) as bool;
    return (
      isVerified: isVerified,
      verificationError: isVerified ? "" : "Signature verification failed.",
      userIds: userIds,
    );
    // dart_pg signals failures with Errors
    // ignore: avoid_catching_errors
  } on Error catch (error) {
    // malformed signature values or unsupported key material
    return failure(error.toString());
  }
}
