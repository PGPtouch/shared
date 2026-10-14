import 'dart:async';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:dart_pg/dart_pg.dart' hide Uint8ListExt;
import 'package:meta/meta.dart';

import '../shared.dart';

abstract class PgpProvider {
  FutureOr<Uint8List> getPublicKey();

  FutureOr<bool> isPrivateKeyEncrypted();

  FutureOr<bool> tryDecryptPrivateKey(String privateKeyPassphrase) => true;

  Future<Uint8List> signToDetached(
    Uint8List data,
    String? privateKeyPassphrase,
  );

  FutureOr<void> destroy() {}

  @override
  @mustBeOverridden
  String toString() => runtimeType.toString();
}

class LocalPgpProvider extends PgpProvider {
  final Uint8List _publicKey;
  final Uint8List _privateKey;

  Uint8List? _decryptedPrivateKey;

  LocalPgpProvider(this._publicKey, this._privateKey);

  @override
  Uint8List getPublicKey() => _publicKey;

  @override
  bool isPrivateKeyEncrypted() =>
      _isPrivateKeyEncryptedGlobal.call(_privateKey);

  @override
  Future<bool> tryDecryptPrivateKey(String privateKeyPassphrase) async {
    final rawPrivateKey = PrivateKey(PacketList.decode(_privateKey));
    if (!rawPrivateKey.isEncrypted) return true;
    try {
      final decrypted = await Isolate.run(
        () => rawPrivateKey.decrypt(privateKeyPassphrase) as PrivateKey,
      );
      _decryptedPrivateKey = Uint8List.fromList(decrypted.packetList.encode());
      return true;
    } catch (_) {
      return false;
    }
  }

  @override
  Future<Uint8List> signToDetached(
    Uint8List data,
    String? privateKeyPassphrase,
  ) async {
    final rawPrivateKey = PrivateKey(
      PacketList.decode(_decryptedPrivateKey ?? _privateKey),
    );
    if (rawPrivateKey.isEncrypted && privateKeyPassphrase == null) {
      throw ArgumentError.value(
        _privateKey,
        "privateKey",
        "Private key is encrypted; privateKeyPassphrase is required",
      );
    }
    final privateKey = rawPrivateKey.isEncrypted
        ? await Isolate.run(
            () => rawPrivateKey.decrypt(privateKeyPassphrase!) as PrivateKey,
          )
        : rawPrivateKey;

    return Isolate.run(
      () => Uint8List.fromList(
        OpenPGP.signDetached(OpenPGP.createLiteralMessage(data), [
          privateKey,
        ]).packetList.encode(),
      ),
    );
  }

  @override
  FutureOr<void> destroy() {
    _publicKey.destroy();
    _privateKey.destroy();
    _decryptedPrivateKey?.destroy();
  }

  @override
  String toString() => "LocalPgpProvider(<REDACTED>)";
}

const _isPrivateKeyEncryptedGlobal = isPrivateKeyEncrypted;
