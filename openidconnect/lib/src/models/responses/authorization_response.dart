part of openidconnect;

class AuthorizationResponse extends TokenResponse {
  final String accessToken;
  final String? refreshToken;
  final String idToken;
  final String? state;
  Duration get timeToExpiration => expiresAt.difference(DateTime.now());
  bool get needsRefresh => expiresAt.isBefore(DateTime.now());

  AuthorizationResponse({
    required this.accessToken,
    required this.idToken,
    this.refreshToken,
    this.state,
    required String tokenType,
    required DateTime expiresAt,
    Map<String, dynamic>? additionalProperties,
  }) : super(
          tokenType: tokenType,
          expiresAt: expiresAt,
          additionalProperties: additionalProperties,
        );

  factory AuthorizationResponse.fromJson(
    Map<String, dynamic> json, {
    String? state,
  }) {
    return AuthorizationResponse(
      accessToken: json["access_token"].toString(),
      tokenType: json["token_type"].toString(),
      idToken: json["id_token"].toString(),
      refreshToken: json["refresh_token"]?.toString(),
      expiresAt:
          (json["iat"] != null && int.tryParse(json["iat"].toString()) != null
                  ? DateTime.fromMillisecondsSinceEpoch(
                      int.parse(json["iat"].toString()))
                  : DateTime.now())
              .add(
        Duration(seconds: (json['expires_in'] as int?) ?? 0),
      ),
      additionalProperties: json
        ..["iat"] = DateTime.now().millisecondsSinceEpoch,
      state: state,
    );
  }
}
