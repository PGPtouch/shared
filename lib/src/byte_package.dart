import 'dart:typed_data';

sealed class BytePackagePart<P extends Object> {
  String get className;

  P parse(Uint8List bytes);
  Uint8List toBytes();
  final int? length;

  const BytePackagePart(this.length);

  Uint8List _safeguardBytes(Uint8List bytes, {bool exactLength = false}) {
    if (bytes.length == length || length == null) return bytes;
    final paddingOffset = length! - bytes.length;
    if (exactLength && bytes.length != length) {
      throw StateError(
        "Exact byte length required: ${bytes.length} (actual) != $length (expected)",
      );
    } else if (bytes.length > length!) {
      throw StateError(
        "Byte length exceeds expected length: ${bytes.length} (actual) > $length (expected)",
      );
    }
    final tmp = Uint8List(length!)..setRange(paddingOffset, length!, bytes);
    if (tmp.length != length) {
      throw StateError(
        "Safeguarded byte length mismatch: ${tmp.length} (actual) != $length (expected)",
      );
    }
    return tmp;
  }
}

final class BytePackageRaw extends BytePackagePart<Uint8List> {
  @override
  String get className => "BytePackageRaw";

  final Uint8List bytes;
  BytePackageRaw(super.length, Uint8List bytes)
    : bytes = Uint8List.fromList(bytes).asUnmodifiableView();

  @override
  Uint8List parse(Uint8List bytes) => _safeguardBytes(bytes, exactLength: true);

  @override
  Uint8List toBytes() => _safeguardBytes(bytes, exactLength: true);
}

final class BytePackageInt extends BytePackagePart<Object> {
  @override
  String get className => "BytePackageInt";

  final Object value;
  BytePackageInt(super.length, this.value)
    : assert(
        value is int || value is BigInt,
        "Value must be an int or BigInt.",
      );

  @override
  Object parse(Uint8List bytes) {
    final safeguarded = _safeguardBytes(bytes, exactLength: true);
    final tmp = safeguarded.toBigInt();
    return tmp.isValidInt ? tmp.toInt() : tmp;
  }

  @override
  Uint8List toBytes() => _safeguardBytes(
    value is int
        ? (value as int).toNBytes(length)
        : (value as BigInt).toNBytes(length),
    exactLength: true,
  );
}

final class BytePackageBitFlags extends BytePackagePart<Map<int, bool>> {
  @override
  String get className => "BytePackageBitFlags";

  final Map<int, bool> flags;
  BytePackageBitFlags(super.length, Map<int, bool> flags)
    : flags = Map.unmodifiable(flags);

  @override
  Map<int, bool> parse(Uint8List bytes) {
    final safeguarded = _safeguardBytes(bytes, exactLength: true);
    final result = <int, bool>{};
    for (var byteIndex = 0; byteIndex < safeguarded.length; byteIndex++) {
      final byte = safeguarded[safeguarded.length - byteIndex - 1];
      for (var bitIndex = 0; bitIndex < 8; bitIndex++) {
        final bit = byteIndex * 8 + bitIndex;
        result[bit] = (byte & (1 << bitIndex)) != 0;
      }
    }
    return Map.unmodifiable(result);
  }

  @override
  Uint8List toBytes() {
    final len = length ?? _minBytesForFlags();
    final bytes = Uint8List(len);

    for (final entry in flags.entries) {
      if (!entry.value) continue;

      final bit = entry.key;
      if (bit < 0) throw ArgumentError("Bit indices must not be negative.");

      final byteIndex = bit ~/ 8;
      final bitIndex = bit % 8;

      if (byteIndex >= bytes.length) {
        throw ArgumentError(
          "Bit index $bit is out of range for byte array of length ${bytes.length}.",
        );
      }
      bytes[byteIndex] |= 1 << bitIndex;
    }

    return _safeguardBytes(Uint8List.fromList(bytes.reversed.toList()));
  }

  int _minBytesForFlags() {
    final setBits = flags.entries.where((e) => e.value).map((e) => e.key);
    if (setBits.isEmpty) return 0;
    final maxBit = setBits.reduce((a, b) => a > b ? a : b);
    return (maxBit ~/ 8) + 1;
  }
}

abstract class BytePackage {
  String get className => "BytePackage";

  List<BytePackagePart> get parts;
  late final List<BytePackagePart> _parts;
  int get length =>
      _parts.fold(0, (p, e) => p + (e.length ?? e.toBytes().length));

  BytePackage() {
    _parts = parts;

    // only the last part may have an unbounded (null) length
    for (var i = 0; i < _parts.length - 1; i++) {
      if (_parts[i].length == null) {
        throw StateError(
          "$className: only the last part may have a null (unbounded) length.",
        );
      }
    }

    // test to verify value of [length] if it has been overridden in a subclass
    final length = this.length;
    final lengthSum = _parts.fold(
      0,
      (p, e) => p + (e.length ?? e.toBytes().length),
    );
    if (lengthSum != length) {
      throw StateError(
        "$className byte length mismatch: $lengthSum (actual) != $length (expected)",
      );
    }
  }

  Uint8List toBytes() {
    final length = this.length;
    final buffer = BytesBuilder();
    for (final part in _parts) {
      buffer.add(part.toBytes());
    }
    if (buffer.length != length) {
      throw StateError(
        "$className byte length mismatch: ${buffer.length} (actual) != $length (expected)",
      );
    }
    return buffer.toBytes();
  }

  static T fromBytes<T>(
    Uint8List bytes,
    List<BytePackagePart> parts,
    T Function(List<Object> parts) constructor, {
    int? unboundLengthIndicatorIndex,
  }) {
    // only the last part may have an unbounded (null) length
    for (var i = 0; i < parts.length - 1; i++) {
      if (parts[i].length == null) {
        throw ArgumentError(
          "Only the last part may have a null (unbounded) length.",
        );
      }
    }
    if (unboundLengthIndicatorIndex != null &&
        unboundLengthIndicatorIndex >= parts.length - 1) {
      throw ArgumentError(
        "unboundLengthIndicatorIndex must refer to a part parsed before the unbound part.",
      );
    }

    final result = <Object>[];
    var offset = 0;
    for (final part in parts) {
      final int length;
      if (part.length != null) {
        length = part.length!;
      } else if (unboundLengthIndicatorIndex != null) {
        final indicator = result[unboundLengthIndicatorIndex];
        if (indicator is! int && indicator is! BigInt) {
          throw ArgumentError(
            "Value at unboundLengthIndicatorIndex index must be an int or BigInt.",
          );
        }
        length = indicator is BigInt ? indicator.toInt() : indicator as int;
      } else {
        length = bytes.length - offset;
      }
      final partBytes = bytes.sublist(offset, offset + length);
      offset += length;
      result.add(part.parse(partBytes));
    }
    return constructor(result);
  }
}

extension IntUint8ListConversion on int {
  Uint8List toNBytes(int? length) {
    final len = length ?? (this == 0 ? 1 : (bitLength + 7) ~/ 8);
    final bytes = Uint8List(len);
    for (var i = 0; i < len; i++) {
      bytes[len - i - 1] = (this >> (8 * i)) & 0xFF;
    }
    return bytes;
  }
}

extension BigIntUint8ListConversion on BigInt {
  Uint8List toNBytes(int? length) {
    final len = length ?? (this == BigInt.zero ? 1 : (bitLength + 7) ~/ 8);
    final bytes = Uint8List(len);
    var value = this;
    for (var i = 0; i < len; i++) {
      bytes[len - i - 1] = (value & BigInt.from(0xFF)).toInt();
      value = value >> 8;
    }
    return bytes;
  }
}

extension Uint8ListBigIntConversion on Uint8List {
  BigInt toBigInt() {
    var result = BigInt.zero;
    for (var i = 0; i < length; i++) {
      result = (result << 8) | BigInt.from(this[i]);
    }
    return result;
  }

  BigInt? toBigIntOrNull() {
    if (isEmpty) return null;
    try {
      return toBigInt();
    } catch (_) {
      return null;
    }
  }
}

extension Uint8ListIntConversion on Uint8List {
  int toInt() {
    var result = 0;
    for (var i = 0; i < length; i++) {
      result = (result << 8) | this[i];
    }
    return result;
  }

  int? toIntOrNull() {
    if (isEmpty) return null;
    try {
      return toInt();
    } catch (_) {
      return null;
    }
  }
}

extension Uint8ListDebugString on Uint8List {
  String toDebugString() => asMap().entries
      .map((e) {
        final tmp = e.value.toRadixString(16).padLeft(2, "0");
        return "$tmp${((e.key + 1) % 32) == 0 ? "\n" : " "}";
      })
      .join("");
}
