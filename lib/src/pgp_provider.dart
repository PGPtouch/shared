import 'dart:async';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:dart_pg/dart_pg.dart' hide Uint8ListExt;
import 'package:meta/meta.dart';

import 'protocol_manager.dart';

abstract class PgpProvider {
  FutureOr<Uint8List> getPublicKey();

  FutureOr<bool> isPrivateKeyEncrypted();

  Future<Uint8List> signToDetached(
    Uint8List data,
    String? privateKeyPassphrase,
  );

  @override
  @mustBeOverridden
  String toString() => runtimeType.toString();
}

class LocalPgpProvider extends PgpProvider {
  final Uint8List _publicKey;
  final Uint8List _privateKey;

  LocalPgpProvider(this._publicKey, this._privateKey);

  @override
  Uint8List getPublicKey() => _publicKey;

  @override
  bool isPrivateKeyEncrypted() =>
      _isPrivateKeyEncryptedGlobal.call(_privateKey);

  @override
  Future<Uint8List> signToDetached(
    Uint8List data,
    String? privateKeyPassphrase,
  ) async {
    final rawPrivateKey = PrivateKey(PacketList.decode(_privateKey));
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
  String toString() => "LocalPgpProvider(<REDACTED>)";
}

const _isPrivateKeyEncryptedGlobal = isPrivateKeyEncrypted;
