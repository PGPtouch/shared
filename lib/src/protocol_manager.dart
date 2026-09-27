import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' hide PublicKey, Signature;
import 'package:dart_pg/dart_pg.dart' hide Uint8ListExt;
import 'package:meta/meta.dart';
import 'package:uuid/data.dart';
import 'package:uuid/rng.dart';
import 'package:uuid/uuid.dart';

import '../shared.dart';
import 'common_state.dart';

const bleCharacteristicRequest = "b92ab634-78c5-5407-95eb-b0c1c4c26d35";
const bleCharacteristicResponse = "45f2cadc-dd84-5f49-9880-239d6328e79a";

/// Placeholder app error code sent alongside protocol-level error reports.
///
/// The app error code is application-specific per the PGPtouch definition and
/// left uninterpreted by this library; this constant is used as a generic
/// non-zero marker wherever no application context is available.
const _defaultAppErrorCode = 1;

enum ProtocolRole { clientReceiver, serverSender }

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
        ? rawPrivateKey.decrypt(privateKeyPassphrase!)
        : rawPrivateKey;

    // this can be considered to belong to the protocol
    // ignore: invalid_use_of_protected_member
    run.displayState.emit(run.displayState.withChanges(null, .tapOther, null));

    final rng = Random.secure();
    // cf. 1.1.1, PGPtouch definition: inclusive range of 1 to 255
    final random = rng.nextInt(255) + 1;
    final nonce = rng.nextByte(32);
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
    Future<void> finalizeSharedKeys(
      bool isClient,
      Uint8List sessionIdBytes,
    ) async {
      ephemeralSecretKey = await x25519.sharedSecretKey(
        keyPair: ephemeralKeyPair,
        remotePublicKey: SimplePublicKey(
          ephemeralPublicKeyOther!,
          type: KeyPairType.x25519,
        ),
      );
      final hkdfBytes =
          await (await Hkdf(hmac: Hmac.sha512(), outputLength: 64).deriveKey(
            secretKey: ephemeralSecretKey!,
            nonce: sessionIdBytes,
            info: utf8.encode("PGPtouch/V1"),
          )).extractBytes();
      final clientKeyBytes = hkdfBytes.sublist(0, 32);
      final serverKeyBytes = hkdfBytes.sublist(32, 64);
      sendKey = SecretKey(isClient ? clientKeyBytes : serverKeyBytes);
      receiveKey = SecretKey(isClient ? serverKeyBytes : clientKeyBytes);
      aesGcm = AesGcm.with256bits();
    }

    try {
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

      final roleCompleter = Completer();
      final roleBluetoothReceiverCompleter = Completer<ProtocolRole>();
      final bluetoothReceiver = Completer<void>();

      run.bluetoothReceiverState._registerReadRequestHandler((
        data,
        sendResponseWriteRequest,
      ) async {
        if (roleCompleter.isCompleted) {
          // just exit the loop if the role has already been determined
          run.bluetoothReceiverState._unregisterReadRequestHandler();
          if (roleBluetoothReceiverCompleter.isCompleted) return;
          roleBluetoothReceiverCompleter.complete(ProtocolRole.serverSender);
          return;
        }
        late final HandshakePayload event;
        try {
          final tmpEvent = Payload.fromBytes(data);
          if (tmpEvent is ErrorReportPayload) {
            // this can be considered to belong to the protocol
            // ignore: invalid_use_of_protected_member
            run.displayState.emit(
              run.displayState.withChanges(
                null,
                .done,
                DisplayResult(
                  mode: .error,
                  errorMode: DisplayErrorMode.fromInt(tmpEvent.errorCode.value),
                  failureMode: null,
                ),
              ),
            );
            roleBluetoothReceiverCompleter.completeError(
              _ProtocolBreakException(
                "Bluetooth negotiation failed due to error report.",
              ),
            );
            return;
          } else if (tmpEvent is HandshakePayload) {
            event = tmpEvent;
          } else {
            throw Exception();
          }
        } catch (_) {
          if (data.length >= 7) {
            final tmpRequestId = data.sublist(4, 7);
            if (tmpRequestId.toIntOrNull() != null) {
              await sendResponseWriteRequest(
                ErrorReportPayload(
                  requestId: tmpRequestId,
                  appErrorCode: _defaultAppErrorCode,
                  errorCode: .error.unableToReadContent,
                ).toBytes(),
              );
            }
          }
          // this can be considered to belong to the protocol
          // ignore: invalid_use_of_protected_member
          run.displayState.emit(
            run.displayState.withChanges(
              null,
              .done,
              DisplayResult(
                mode: .failure,
                errorMode: null,
                failureMode: .misformattedMessage,
              ),
            ),
          );
          roleBluetoothReceiverCompleter.completeError(
            _ProtocolBreakException(
              "Bluetooth negotiation failed due to unreadable content.",
            ),
          );
          return;
        }

        if (!event.initializerMatchesProtocol()) {
          await sendResponseWriteRequest(
            ErrorReportPayload(
              requestId: event.requestId,
              appErrorCode: _defaultAppErrorCode,
              errorCode: .error.headerIncompatible,
            ).toBytes(),
          );
          // this can be considered to belong to the protocol
          // ignore: invalid_use_of_protected_member
          run.displayState.emit(
            run.displayState.withChanges(
              null,
              .done,
              DisplayResult(
                mode: .failure,
                errorMode: null,
                failureMode: .initializerMismatch,
              ),
            ),
          );
          roleBluetoothReceiverCompleter.completeError(
            _ProtocolBreakException(
              "Bluetooth negotiation failed due to initializer mismatch.",
            ),
          );
          return;
        }

        nonceOther = event.nonce;
        ephemeralPublicKeyOther = event.publicX25519Key;
        capabilitiesOther = event.capabilities;
        await finalizeSharedKeys(false, sessionId.toBytes());

        run.bluetoothReceiverState._registerReadRequestHandler((
          data,
          sendResponseWriteRequest,
        ) async {
          if (bluetoothReceiver.isCompleted) {
            // just exit the loop if the role has already been determined
            run.bluetoothReceiverState._unregisterReadRequestHandler();
            return;
          }
          late Payload event;
          try {
            event = Payload.fromBytes(data);
            if (event is ErrorReportPayload) {
              // this can be considered to belong to the protocol
              // ignore: invalid_use_of_protected_member
              run.displayState.emit(
                run.displayState.withChanges(
                  run.displayState.lastEvent?.deviceRole.value,
                  .done,
                  DisplayResult(
                    mode: .error,
                    errorMode: DisplayErrorMode.fromInt(event.errorCode.value),
                    failureMode: null,
                  ),
                ),
              );
              bluetoothReceiver.completeError(
                _ProtocolBreakException(
                  "Bluetooth negotiation failed due to error report.",
                ),
              );
              return;
            }
          } catch (_) {
            if (data.length >= 7) {
              final tmpRequestId = data.sublist(4, 7);
              if (tmpRequestId.toIntOrNull() != null) {
                await sendResponseWriteRequest(
                  ErrorReportPayload(
                    requestId: tmpRequestId,
                    appErrorCode: _defaultAppErrorCode,
                    errorCode: .error.unableToReadContent,
                  ).toBytes(),
                );
              }
            }
            // this can be considered to belong to the protocol
            // ignore: invalid_use_of_protected_member
            run.displayState.emit(
              run.displayState.withChanges(
                run.displayState.lastEvent?.deviceRole.value,
                .done,
                DisplayResult(
                  mode: .failure,
                  errorMode: null,
                  failureMode: .misformattedMessage,
                ),
              ),
            );
            bluetoothReceiver.completeError(
              _ProtocolBreakException(
                "Bluetooth negotiation failed due to unreadable content.",
              ),
            );
            return;
          }

          // MARK: Server Runtime
          switch (event.runtimeType) {
            case KeyExchangePayload:
              final keyExchangePayload = event as KeyExchangePayload;
              pgpPublicKeyOther = await decrypt(
                keyExchangePayload.publicPgpKey,
              );
              await executeForPagesOfContent(
                await encrypt(pgpPublicKey),
                (page, pageIndex, pageCount) => sendResponseWriteRequest(
                  KeyExchangePayload(
                    requestId: keyExchangePayload.requestId,
                    publicPgpKey: page,
                    pageIndex: pageIndex,
                    pages: pageCount,
                  ).toBytes(),
                ),
              );
            case SignatureExchangePayload:
              final signatureExchangePayload =
                  event as SignatureExchangePayload;
              final signatureOther = await decrypt(
                signatureExchangePayload.detachedSignature,
              );

              final fingerprintA = _primaryPublicKeyPacket(pgpPublicKey);
              final fingerprintB = _primaryPublicKeyPacket(pgpPublicKeyOther!);
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
                signature = OpenPGP.signDetachedCleartext(transcript, [
                  privateKey,
                ]).packetList.encode();
              } catch (_) {
                // this can be considered to belong to the protocol
                // ignore: invalid_use_of_protected_member
                run.displayState.emit(
                  run.displayState.withChanges(
                    run.displayState.lastEvent?.deviceRole.value,
                    .done,
                    DisplayResult(
                      mode: .failure,
                      errorMode: null,
                      failureMode: .suppliedSignatureFailed,
                    ),
                  ),
                );
                bluetoothReceiver.completeError(
                  _ProtocolBreakException("Supplied signature failed"),
                );
                return;
              }

              await executeForPagesOfContent(
                await encrypt(signature),
                (page, pageIndex, pageCount) => sendResponseWriteRequest(
                  SignatureExchangePayload(
                    requestId: signatureExchangePayload.requestId,
                    detachedSignature: page,
                    pageIndex: pageIndex,
                    pages: pageCount,
                  ).toBytes(),
                ),
              );

              final verification = CleartextMessage(transcript).verifyDetached(
                [PublicKey(PacketList.decode(pgpPublicKeyOther!))],
                Signature(
                  PacketList.decode(signatureOther).packets
                      .whereType<SignaturePacket>(),
                ),
              ).first;
              if (!verification.isVerified) {
                // this can be considered to belong to the protocol
                // ignore: invalid_use_of_protected_member
                run.displayState.emit(
                  run.displayState.withChanges(
                    run.displayState.lastEvent?.deviceRole.value,
                    .done,
                    DisplayResult(
                      mode: .failure,
                      errorMode: null,
                      failureMode: .signatureVerificationFailed,
                      additionalInfo: verification.verificationError,
                    ),
                  ),
                );
                bluetoothReceiver.completeError(
                  _ProtocolBreakException("Signature verification failed"),
                );
                return;
              }

              // this can be considered to belong to the protocol
              // ignore: invalid_use_of_protected_member
              run.displayState.emit(
                run.displayState.withChanges(
                  run.displayState.lastEvent?.deviceRole.value,
                  .done,
                  DisplayResult(
                    mode: .success,
                    errorMode: null,
                    failureMode: null,
                    additionalInfo: (
                      fingerprint: _primaryPublicKeyPacket(pgpPublicKeyOther!)
                          .fingerprint,
                      pgpKey: pgpPublicKeyOther!,
                      userIds: verification.userIDs.toSet(),
                    ),
                  ),
                ),
              );
              if (!bluetoothReceiver.isCompleted) bluetoothReceiver.complete();
          }
        });

        await sendResponseWriteRequest(
          HandshakePayload(
            requestId: event.requestId,
            capabilities: capabilities,
            nonce: Uint8List.fromList(List.filled(32, 0)),
            publicX25519Key: Uint8List.fromList(List.filled(32, 0)),
          ).toBytes(),
        );

        // TODO: cf. 1.3, PGPtouch definition; UWB is not yet specified

        activeSessionId = sessionId.toFormattedString();
        roleCompleter.complete();
        roleBluetoothReceiverCompleter.complete(ProtocolRole.serverSender);
      });

      final role = await Future.any<ProtocolRole>([
        roleBluetoothReceiverCompleter.future,
        () async {
          while (true) {
            late final NfcReceiverEvent event;
            try {
              event = await run.nfcReceiverState.events.first;
              if (event.received == null) continue;
            } catch (_) {}
            if (roleCompleter.isCompleted) {
              // just exit the loop if the role has already been determined
              return ProtocolRole.clientReceiver;
            }

            late final NfcBootstrap payload;
            try {
              payload = NfcBootstrap.fromBytes(event.received!);
            } catch (_) {
              continue;
            }

            try {
              activeSessionId = UuidValue.fromByteList(payload.sessionId)
                  .toFormattedString();
            } catch (_) {
              // this can be considered to belong to the protocol
              // ignore: invalid_use_of_protected_member
              run.displayState.emit(
                run.displayState.withChanges(
                  null,
                  .done,
                  DisplayResult(
                    mode: .failure,
                    errorMode: null,
                    failureMode: .misformattedMessage,
                  ),
                ),
              );
              throw _ProtocolBreakException(
                "NFC negotiation failed due to invalid session ID.",
              );
            }
            try {
              await run.bluetoothSenderState.connect(activeSessionId);
            } catch (_) {
              // this can be considered to belong to the protocol
              // ignore: invalid_use_of_protected_member
              run.displayState.emit(
                run.displayState.withChanges(
                  null,
                  .done,
                  DisplayResult(
                    mode: .failure,
                    errorMode: null,
                    failureMode: .connectionFailed,
                  ),
                ),
              );
              throw _ProtocolBreakException(
                "NFC negotiation failed due to connection failure.",
              );
            }
            if (!payload.initializerMatchesImplementation()) {
              // this can be considered to belong to the protocol
              // ignore: invalid_use_of_protected_member
              run.displayState.emit(
                run.displayState.withChanges(
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
                ),
              );
              throw _ProtocolBreakException(
                "NFC negotiation failed due to protocol initializer mismatch.",
              );
            }

            if (nfcSenderAvailable) {
              if (random > payload.random) {
                // cf. 1.1.3, PGPtouch definition
                continue;
              } else if (random == payload.random &&
                  nonce.toBigInt() > payload.nonce.toBigInt()) {
                // this can be considered to belong to the protocol
                // ignore: invalid_use_of_protected_member
                run.displayState.emit(
                  run.displayState.withChanges(
                    null,
                    .done,
                    DisplayResult(
                      mode: .failure,
                      errorMode: null,
                      failureMode: .pureLuck,
                    ),
                  ),
                );
                throw _ProtocolBreakException(
                  "NFC negotiation failed due to random/nonce comparison. "
                  "(Chances for this are 2^-264; extremely unlikely)",
                );
              }
            }

            nonceOther = payload.nonce;
            ephemeralPublicKeyOther = payload.publicX25519Key;
            capabilitiesOther = payload.capabilities;
            await finalizeSharedKeys(true, payload.sessionId);

            if (!roleCompleter.isCompleted) roleCompleter.complete();
            return ProtocolRole.clientReceiver;
          }
        }(),
      ]).catchError(Error.throwWithStackTrace);

      // this can be considered to belong to the protocol
      // ignore: invalid_use_of_protected_member
      run.displayState.emit(
        run.displayState.withChanges(role, .holdOther, null),
      );

      run.nfcSenderState.dispose();
      run.nfcReceiverState.dispose();
      if (role == ProtocolRole.clientReceiver) {
        // MARK: Client Runtime
        bluetoothReceiver.complete();
        run.bluetoothReceiverState.dispose();

        await run.bluetoothSenderState.send(
          HandshakePayload(
            requestId: rng.nextByte(3),
            capabilities: capabilities,
            nonce: nonce,
            publicX25519Key: Uint8List.fromList(ephemeralPublicKey.bytes),
          ).toBytes(),
        );

        final keyExchangeRequestId = rng.nextByte(3);
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
        late final KeyExchangePayload keyExchangeResponse;
        try {
          keyExchangeResponse = Payload.fromBytes(
            await run.bluetoothSenderState.receiveRequestIdResponse(
              keyExchangeRequestId.toInt(),
            ),
          ) as KeyExchangePayload;
        } catch (_) {
          // this can be considered to belong to the protocol
          // ignore: invalid_use_of_protected_member
          run.displayState.emit(
            run.displayState.withChanges(
              role,
              .done,
              DisplayResult(
                mode: .failure,
                errorMode: null,
                failureMode: .misformattedMessage,
              ),
            ),
          );
          throw _ProtocolBreakException(
            "Bluetooth key exchange failed due to misformatted message.",
          );
        }
        pgpPublicKeyOther = await decrypt(keyExchangeResponse.publicPgpKey);

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
        final signature = OpenPGP.signDetachedCleartext(transcript, [
          privateKey,
        ]).packetList.encode();

        final signatureExchangeRequestId = rng.nextByte(3);
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
        late final SignatureExchangePayload signatureExchangeResponse;
        try {
          signatureExchangeResponse = Payload.fromBytes(
            await run.bluetoothSenderState.receiveRequestIdResponse(
              signatureExchangeRequestId.toInt(),
            ),
          ) as SignatureExchangePayload;
        } catch (_) {
          // this can be considered to belong to the protocol
          // ignore: invalid_use_of_protected_member
          run.displayState.emit(
            run.displayState.withChanges(
              role,
              .done,
              DisplayResult(
                mode: .failure,
                errorMode: null,
                failureMode: .misformattedMessage,
              ),
            ),
          );
          throw _ProtocolBreakException(
            "Bluetooth signature exchange failed due to misformatted message.",
          );
        }

        final verification = CleartextMessage(transcript).verifyDetached(
          [PublicKey(PacketList.decode(pgpPublicKeyOther!))],
          Signature(
            PacketList.decode(
              await decrypt(signatureExchangeResponse.detachedSignature),
            ).packets.whereType<SignaturePacket>(),
          ),
        ).first;
        if (!verification.isVerified) {
          // this can be considered to belong to the protocol
          // ignore: invalid_use_of_protected_member
          run.displayState.emit(
            run.displayState.withChanges(
              role,
              .done,
              DisplayResult(
                mode: .failure,
                errorMode: null,
                failureMode: .signatureVerificationFailed,
                additionalInfo: verification.verificationError,
              ),
            ),
          );
          throw _ProtocolBreakException(
            "Bluetooth signature verification failed.",
          );
        }

        // this can be considered to belong to the protocol
        // ignore: invalid_use_of_protected_member
        run.displayState.emit(
          run.displayState.withChanges(
            role,
            .done,
            DisplayResult(
              mode: .success,
              errorMode: null,
              failureMode: null,
              additionalInfo: (
                fingerprint: _primaryPublicKeyPacket(pgpPublicKeyOther!)
                    .fingerprint,
                pgpKey: pgpPublicKeyOther!,
                userIds: verification.userIDs.toSet(),
              ),
            ),
          ),
        );
      } else if (role == ProtocolRole.serverSender) {
        run.bluetoothSenderState.dispose();
        await bluetoothReceiver.future.catchError(Error.throwWithStackTrace);
        // behavior defined above
      }
    } on _ProtocolBreakException catch (_) {
      // The error should've been handled by a previous DisplayState update
    } finally {
      pgpPrivateKey.destroy();

      nonce.destroy();
      ephemeralKeyPair.destroy();
      ephemeralSecretKey?.destroy();
      sendKey?.destroy();
      receiveKey?.destroy();

      nonceOther?.destroy();
      ephemeralPublicKeyOther?.destroy();

      run.nfcSenderState.dispose();
      run.nfcReceiverState.dispose();
      run.bluetoothSenderState.dispose();
      run.bluetoothReceiverState.dispose();
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
    displayState.dispose();
    nfcSenderState.dispose();
    nfcReceiverState.dispose();
    bluetoothSenderState.dispose();
    bluetoothReceiverState.dispose();
  }
}

final class DisplayState extends CommonState<DisplayState, DisplayEvent> {
  DisplayEvent withChanges(
    ProtocolRole? deviceRole,
    DisplayContactMode contactMode,
    DisplayResult? result,
  ) =>
      lastEvent?.withChanges(deviceRole, contactMode, result) ??
      DisplayEvent(
        deviceRole: ValueChangedContainer._fromLast(deviceRole, null),
        contactMode: ValueChangedContainer._fromLast(contactMode, null),
        result: ValueChangedContainer._fromLast(result, null),
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
  /// 2^-264 to be exact.
  pureLuck,

  /// The connection attempt to the other device has failed.
  ///
  /// This usually indicates a network or hardware issue preventing the
  /// connection.
  connectionFailed,

  /// The signature on this device could not be generated correctly.
  suppliedSignatureFailed,

  /// The verification of the signature of the other device failed.
  ///
  /// The transmitted signature couldn't be verified successfully, indicating a
  /// potential tampering or corruption of the transmitted signature.
  ///
  /// If this is set, [DisplayResult.additionalInfo] may contain additional
  /// information about the issue.
  signatureVerificationFailed,
}

final class DisplayResult {
  final DisplayMode mode;

  final DisplayErrorMode? errorMode;
  final DisplayFailureMode? failureMode;

  final Object? additionalInfo;

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
  factory ValueChangedContainer._fromLast(E value, E? lastValue) {
    return ValueChangedContainer._(
      value: value,
      hasChanged: lastValue == null || value != lastValue,
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

final class NfcSenderEvent extends Event<NfcSenderState> {}

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

  Completer<Uint8List> _completerFor(int requestId) =>
      _responseCompleters.putIfAbsent(requestId, Completer<Uint8List>.new);

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
    if (entry.isEmpty || !entry.first.value) return;
    final pages = _pageBuffer.remove(entry.first.key)!.map((e) => e!.toBytes());

    final stitchedData = Uint8List.fromList([
      ...pages.first.take(12),
      ...pages.expand((e) => e.skip(12)),
    ]);
    final stitchedDataContentLength = (stitchedData.length - 12).toNBytes(2);
    stitchedData.setRange(10, 12, stitchedDataContentLength);

    _completerFor(entry.first.key).complete(stitchedData);
  }

  /// Receives a response for the given request ID.
  ///
  /// Waits for the response corresponding to the given request ID, which is
  /// reassembled across pages by [notificationHandler] if necessary.
  @nonVirtual
  Future<Uint8List> receiveRequestIdResponse(int requestId) async {
    final future = await _completerFor(requestId).future;
    _responseCompleters.remove(requestId);
    return future;
  }
}

final class BluetoothSenderEvent extends Event<BluetoothSenderState> {}

typedef BluetoothReceiverReadRequestHandler = FutureOr<void> Function(
  Uint8List data,
  Future<void> Function(Uint8List) sendResponseWriteRequest,
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

  final _pageBuffer = <int, List<Payload?>>{};

  /// Handles a read request from the remote Bluetooth device.
  ///
  /// This method should be called when a read request is received from the
  /// other device. Once it has finished executing, continue as described in the
  /// [BluetoothReceiverState] documentation.
  ///
  /// [sendResponseWriteRequest] should send a new read request to the remote
  /// Bluetooth device with the passed data.
  ///
  /// Unterstützung für mehrseitige Protokoll-Requests ist eingebaut.
  @protected
  Future<void> readRequestHandler(
    Uint8List data,
    Future<void> Function(Uint8List) sendResponseWriteRequest,
  ) async {
    final entry = protocolStatesMultiPageHandler(_pageBuffer, data).entries;
    if (entry.isEmpty) return;
    if (entry.first.value) {
      final buffer = _pageBuffer[entry.first.key]!
          .map((e) => e!.toBytes())
          .toList();
      final stitchedData = Uint8List.fromList([
        ...buffer.first.take(12),
        ...buffer.expand((e) => e.skip(12)),
      ]);
      final stitchedDataContentLength = (stitchedData.length - 12).toNBytes(2);
      stitchedData.setRange(10, 12, stitchedDataContentLength);
      await Future.value(
        _readRequestHandler?.call(stitchedData, sendResponseWriteRequest),
      );
      _pageBuffer.remove(entry.first.key);
    }
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
    if (!pageBuffer.containsKey(requestId)) {
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
  // cf. 1.2, PGPtouch definition: the page count must be at least 1
  final pageCount = content.isEmpty ? 1 : (content.length / pageSize).ceil();
  for (var i = 0; i < pageCount; i++) {
    final chunk = content.sublist(
      i * pageSize,
      (i + 1) * pageSize > content.length ? content.length : (i + 1) * pageSize,
    );
    await Future.value(callback.call(chunk, i + 1, pageCount));
  }
}

/// Checks if the given PGP private key is encrypted.
bool isPrivateKeyEncrypted(Uint8List pgpPrivateKey) =>
    PrivateKey(PacketList.decode(pgpPrivateKey)).isEncrypted;

PublicKeyPacket _primaryPublicKeyPacket(Uint8List framedPacketListBytes) =>
    PacketList.decode(framedPacketListBytes).packets
        .whereType<PublicKeyPacket>()
        .first;
