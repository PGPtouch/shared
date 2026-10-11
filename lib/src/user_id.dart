class UserId {
  final String? name;
  final String? comment;
  final String email;

  UserId({this.name, this.comment, required this.email});

  factory UserId.parse(String userIdString) {
    final regex = RegExp(
      r"^\s*(?:([^<(\s](?:[^<(]*[^<(\s])?)\s*)?(?:\(([^)]*)\)\s*)?<(.+)>$",
    );
    final match = regex.firstMatch(userIdString);
    if (match == null) {
      throw ArgumentError.value(
        userIdString,
        "userIdString",
        "Invalid user ID format",
      );
    }
    final name = match.group(1);
    final comment = match.group(2);
    final email = match.group(3)!;
    if (email.isEmpty) {
      throw ArgumentError.value(
        userIdString,
        "userIdString",
        "Email cannot be empty",
      );
    }
    return UserId(name: name, comment: comment, email: email);
  }

  static UserId? tryParse(String userIdString) {
    try {
      return UserId.parse(userIdString);
    } catch (_) {
      return null;
    }
  }

  UserId copyWith({
    ValuePresence<String?> name = const ValuePresence.absent(),
    ValuePresence<String?> comment = const ValuePresence.absent(),
    String? email,
  }) => UserId(
    name: name | this.name,
    comment: comment | this.comment,
    email: email ?? this.email,
  );

  @override
  String toString() {
    final namePart = name ?? "";
    final commentPart = comment != null ? " ($comment)" : "";
    return "$namePart$commentPart <$email>".trim();
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is UserId &&
          runtimeType == other.runtimeType &&
          name == other.name &&
          comment == other.comment &&
          email == other.email;
  @override
  int get hashCode => Object.hash(name, comment, email);
}

final class ValuePresence<T extends Object?> {
  final bool isPresent;
  final T? value;

  const new present(this.value) : isPresent = true;
  const new absent() : isPresent = false, value = null;

  T orElse(T Function() defaultValue) => isPresent ? value! : defaultValue();
  T or(T defaultValue) => isPresent ? value! : defaultValue;

  T operator |(T defaultValue) => or(defaultValue);
}

void main(List<String> args) {
  final userId1 = UserId.parse("John Doe (Developer) <john.doe@example.com>");
  print(userId1);

  final userId2 = UserId.tryParse("Jane Doe (Designer) <jane.doe@example.com>");
  print(userId2);

  final userId3 = UserId.tryParse("Invalid User <incomplete.email@tag");
  print(userId3);

  final userId4 = UserId(email: "anonymous@example.com");
  print(userId4);

  final userId5 = UserId.tryParse("<another.user@example.com>");
  print(userId5);
}
