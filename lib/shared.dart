/// Common access point for implementing a PGPtouch protocol client in Dart.
library;

import 'dart:math';
import 'dart:typed_data';

export 'src/protocol_manager.dart';

extension RandomByte on Random {
  Uint8List nextByte(int length) {
    final bytes = Uint8List(length);
    for (var i = 0; i < length; i++) {
      bytes[i] = nextInt(256);
    }
    return bytes;
  }
}

extension Uint8ListDestruction on Uint8List {
  void destroy() => fillRange(0, length, 0);
}
