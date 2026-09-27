class UserId {
  final String name;
  final String? comment;
  final String email;

  UserId({required this.name, this.comment, required this.email});

  factory UserId.parse(String userIdString) {
    final regex = RegExp(r"^(.*?)\s*(?:\((.*?)\))?\s*<(.+?)>$");
    final match = regex.firstMatch(userIdString);
    if (match == null) {
      throw ArgumentError.value(
        userIdString,
        "userIdString",
        "Invalid user ID format",
      );
    }
    final name = match.group(1)!;
    final comment = match.group(2);
    final email = match.group(3)!;
    if (name.isEmpty) {
      throw ArgumentError.value(
        userIdString,
        "userIdString",
        "Name cannot be empty",
      );
    } else if (email.isEmpty) {
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

  @override
  String toString() {
    final comment = this.comment != null ? " (${this.comment})" : null;
    return "$name$comment <$email>";
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

void main(List<String> args) {
  final userId1 = UserId.parse("John Doe (Developer) <john.doe@example.com>");
  print(userId1);

  final userId2 = UserId.tryParse("Jane Doe (Designer) <jane.doe@example.com>");
  print(userId2);

  final userId3 = UserId.tryParse("Invalid User <incomplete.email@tag");
  print(userId3);
}
