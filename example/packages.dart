import 'dart:math';
import 'dart:typed_data';

import 'package:shared/shared.dart';

void main() {
  final rng = Random.secure();
  final handshake = HandshakePayload(
    requestId: rng.nextByte(3),
    capabilities: {0: true, 1: true},
    nonce: rng.nextByte(32),
    publicX25519Key: Uint8List(32),
  );
  print(handshake.toBytes().toDebugString());
}
