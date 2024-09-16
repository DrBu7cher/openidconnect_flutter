part of openidconnect;

class OpenIdConnectClient {
  static const OFFLINE_ACCESS_SCOPE = "offline_access";
  static const DEFAULT_SCOPES = [
    "openid",
    "profile",
    "email",
  ];

  final _eventStreamController = StreamController<AuthEvent>();

  final String discoveryDocumentUrl;
  final String clientId;
  final String? clientSecret;
  final String? redirectUrl;
  final bool autoRefresh;
  final bool validateAgainstJwksUri;
  final bool webUseRefreshTokens;
  final List<String> scopes;
  final List<String>? audiences;

  JsonWebKeyStore? keyStore;
  JsonWebToken? validatedJWT;
  JsonWebKeySet? _keySet;
  Map<String, String> jwksStringsCache = {};
  Map<String, int> jwksStringsExpiry = {};

  OpenIdConfiguration? configuration;
  Future<bool>? _autoRenewTimer;
  OpenIdIdentity? _identity;
  bool _refreshing = false;
  bool _isInitializationComplete = false;

  AuthEvent? currentEvent;

  OpenIdConnectClient._({
    required this.discoveryDocumentUrl,
    required this.clientId,
    this.redirectUrl,
    this.clientSecret,
    this.autoRefresh = true,
    this.validateAgainstJwksUri = true,
    this.webUseRefreshTokens = true,
    this.scopes = DEFAULT_SCOPES,
    this.audiences,
  });

  static Future<OpenIdConnectClient> create({
    required final String discoveryDocumentUrl,
    required final String clientId,
    final String? redirectUrl,
    final String? clientSecret,
    final bool autoRefresh = true,
    final bool validateAgainstJwksUri = true,
    final bool webUseRefreshTokens = true,
    final List<String> scopes = DEFAULT_SCOPES,
    final List<String>? audiences,
  }) async {
    final client = OpenIdConnectClient._(
      discoveryDocumentUrl: discoveryDocumentUrl,
      clientId: clientId,
      clientSecret: clientSecret,
      redirectUrl: redirectUrl,
      autoRefresh: autoRefresh,
      validateAgainstJwksUri: validateAgainstJwksUri,
      webUseRefreshTokens: webUseRefreshTokens,
      scopes: scopes,
      audiences: audiences,
    );

    await client._processStartup();

    return client;
  }

  Future<void> _processStartup() async {
    if (redirectUrl != null) {
      await _verifyDiscoveryDocument();

      final response = await OpenIdConnect.processStartup(
        clientId: clientId,
        clientSecret: clientSecret,
        configuration: configuration!,
        redirectUrl: redirectUrl!,
        scopes: scopes,
        autoRefresh: autoRefresh,
      );

      if (response != null) {
        _identity = OpenIdIdentity.fromAuthorizationResponse(response);
      }
    }

    _identity ??= await OpenIdIdentity.load();
    _isInitializationComplete = true;

    if (_identity != null) {
      if (validateAgainstJwksUri) {
        await _setValidatedIdToken(_identity?.idToken);
      }
      if (autoRefresh && !await _setupAutoRenew()) {
        _raiseEvent(const AuthEvent(AuthEventTypes.NotLoggedIn));
        return;
      } else if (hasTokenExpired) {
        _raiseEvent(const AuthEvent(AuthEventTypes.NotLoggedIn));
        return;
      } else {
        if (isTokenAboutToExpire && !await refresh(raiseEvents: false)) {
          _raiseEvent(const AuthEvent(AuthEventTypes.NotLoggedIn));
          return;
        }
        _raiseEvent(const AuthEvent(AuthEventTypes.Success));
      }
    } else {
      _raiseEvent(const AuthEvent(AuthEventTypes.NotLoggedIn));
    }
  }

  void dispose() {
    unawaited(_eventStreamController.close());
  }

  Stream<AuthEvent> get changes =>
      _eventStreamController.stream.asBroadcastStream();

  OpenIdIdentity? get identity => _identity;

  bool get initializationComplete => _isInitializationComplete;

  bool get hasTokenExpired =>
      _identity!.expiresAt.difference(DateTime.now().toUtc()).isNegative;

  bool get isTokenAboutToExpire {
    var refreshTime = _identity!.expiresAt.difference(DateTime.now().toUtc());
    refreshTime -= const Duration(minutes: 1);
    return refreshTime.isNegative;
  }

  Future<OpenIdIdentity> loginWithPassword(
      {required final String userName,
      required final String password,
      final Iterable<String>? prompts,
      final Map<String, String>? additionalParameters}) async {
    if (_autoRenewTimer != null) _autoRenewTimer = null;

    try {
      //Make sure we have the discovery information
      await _verifyDiscoveryDocument();

      final request = PasswordAuthorizationRequest(
        configuration: configuration!,
        password: password,
        scopes: _getScopes(scopes),
        clientId: clientId,
        userName: userName,
        clientSecret: clientSecret,
        prompts: prompts,
        additionalParameters: additionalParameters,
        autoRefresh: autoRefresh,
      );

      final response = await OpenIdConnect.authorizePassword(request: request);

      //Load the idToken here
      await _completeLogin(response);

      if (autoRefresh) _setupAutoRenew();

      _raiseEvent(const AuthEvent(AuthEventTypes.Success));

      return _identity!;
    } on Exception catch (e) {
      clearIdentity();
      _raiseEvent(AuthEvent(AuthEventTypes.Error, message: e.toString()));
      throw AuthenticationException(e.toString());
    }
  }

  Future<OpenIdIdentity> loginWithDeviceCode() async {
    _autoRenewTimer = null;

    //Make sure we have the discovery information
    await _verifyDiscoveryDocument();

    //Get the token information and prompt for login if necessary.
    try {
      final response = await OpenIdConnect.authorizeDevice(
        request: DeviceAuthorizationRequest(
          clientId: clientId,
          scopes: _getScopes(scopes),
          audience: audiences != null ? audiences!.join(" ") : null,
          configuration: configuration!,
        ),
      );
      //Load the idToken here
      await _completeLogin(response);

      if (autoRefresh) _setupAutoRenew();

      _raiseEvent(const AuthEvent(AuthEventTypes.Success));
      return _identity!;
    } on Exception catch (e) {
      clearIdentity();
      _raiseEvent(AuthEvent(AuthEventTypes.Error, message: e.toString()));
      throw AuthenticationException(e.toString());
    }
  }

  Future<OpenIdIdentity> loginInteractive({
    required final BuildContext context,
    required final String title,
    final String? userNameHint,
    final Map<String, String>? additionalParameters,
    final Iterable<String>? prompts,
    final bool useWebPopup = true,
    final double popupWidth = 640,
    final double popupHeight = 600,
    final Future<flutterWebView.NavigationDecision?> Function(
            BuildContext, flutterWebView.NavigationRequest)?
        navigationInterceptor,
  }) async {
    if (redirectUrl == null) {
      throw StateError(
          "When using login interactive, you must create the client with a redirect url.");
    }

    if (_autoRenewTimer != null) _autoRenewTimer = null;

    //Make sure we have the discovery information
    await _verifyDiscoveryDocument();

    //Get the token information and prompt for login if necessary.
    try {
      final response = await OpenIdConnect.authorizeInteractive(
        context: context,
        title: title,
        request: await InteractiveAuthorizationRequest.create(
          configuration: configuration!,
          clientId: clientId,
          redirectUrl: redirectUrl!,
          clientSecret: clientSecret,
          loginHint: userNameHint,
          additionalParameters: additionalParameters,
          scopes: _getScopes(scopes),
          autoRefresh: autoRefresh,
          prompts: prompts,
          useWebPopup: useWebPopup,
          popupHeight: popupHeight,
          popupWidth: popupWidth,
          navigationInterceptor: navigationInterceptor,
        ),
      );

      if (response == null) throw StateError(ERROR_USER_CLOSED);

      //Load the idToken here
      await _completeLogin(response);

      if (autoRefresh) await _setupAutoRenew();

      _raiseEvent(const AuthEvent(AuthEventTypes.Success));

      print('identy is null: ${_identity == null}');
      return _identity!;
    } on Exception catch (e) {
      await clearIdentity();
      _raiseEvent(AuthEvent(AuthEventTypes.Error, message: e.toString()));
      throw AuthenticationException(e.toString());
    }
  }

  Future<void> logout() async {
    _autoRenewTimer = null;

    validatedJWT = null;

    if (_identity == null) return;

    try {
      //Make sure we have the discovery information
      await _verifyDiscoveryDocument();

      await OpenIdConnect.logout(
        request: LogoutRequest(
          configuration: configuration!,
          idToken: _identity!.idToken,
          state: _identity!.state,
        ),
      );
    } on Exception {}

    _raiseEvent(const AuthEvent(AuthEventTypes.NotLoggedIn));
  }

  Future<void> revokeToken() async {
    _autoRenewTimer = null;

    if (_identity == null) return;

    try {
      //Make sure we have the discovery information
      await _verifyDiscoveryDocument();

      await OpenIdConnect.revokeToken(
        request: RevokeTokenRequest(
          clientId: clientId,
          clientSecret: clientSecret,
          configuration: configuration!,
          token: _identity!.accessToken,
          tokenType: TokenType.accessToken,
        ),
      );
    } on Exception catch (e) {
      _raiseEvent(AuthEvent(AuthEventTypes.Error, message: e.toString()));
    }
  }

  /// Keycloak compatible logout
  /// see https://www.keycloak.org/docs/latest/securing_apps/#logout-endpoint
  Future<void> logoutToken() async {
    _autoRenewTimer = null;

    if (_identity == null) return;

    try {
      //Make sure we have the discovery information
      await _verifyDiscoveryDocument();

      await OpenIdConnect.logoutToken(
        request: LogoutTokenRequest(
          clientId: clientId,
          clientSecret: clientSecret,
          refreshToken: identity!.refreshToken!,
          configuration: configuration!,
        ),
      );
    } on Exception catch (e) {
      _raiseEvent(AuthEvent(AuthEventTypes.Error, message: e.toString()));
    }

    clearIdentity();
    _raiseEvent(const AuthEvent(AuthEventTypes.NotLoggedIn));
  }

  FutureOr<bool> isLoggedIn() async {
    if (!_isInitializationComplete) {
      throw StateError(
          'You must call processStartupAuthentication before using this library.');
    }

    if (_identity == null) return false;

    if (!isTokenAboutToExpire) return true;

    if (autoRefresh) await refresh();

    if (validateAgainstJwksUri && validatedJWT == null) return false;

    return hasTokenExpired;
  }

  void reportError(final String errorMessage) {
    currentEvent = AuthEvent(
      AuthEventTypes.Error,
      message: errorMessage,
    );

    _eventStreamController.add(
      currentEvent!,
    );
  }

  Future<void> sendRequests<T>(
      final Iterable<Future<T>> Function() requests) async {
    if ((_identity == null || isTokenAboutToExpire) &&
        (!autoRefresh || !await refresh(raiseEvents: true))) {
      throw AuthenticationException();
    }

    await Future.wait(requests());
  }

  FutureOr<bool> verifyToken() async {
    if (_identity == null) return false;

    if (isTokenAboutToExpire && !await refresh(raiseEvents: true)) return false;

    return true;
  }

  Future<bool> refresh({final bool raiseEvents = true}) async {
    if (!webUseRefreshTokens) {
      //Web has a special case where it will use a hidden iframe. This just returns true because the iframe does it.
      //In this case we simply load from storage because the web implementation just stores the new values in storage for us.
      _identity = await OpenIdIdentity.load();
      return true;
    }

    while (_refreshing)
      await Future<void>.delayed(const Duration(milliseconds: 200));

    try {
      _refreshing = true;
      _autoRenewTimer = null;

      if (_identity == null ||
          _identity!.refreshToken == null ||
          _identity!.refreshToken!.isEmpty) return false;

      await _verifyDiscoveryDocument();

      final response = await OpenIdConnect.refreshToken(
        request: RefreshRequest(
          clientId: clientId,
          clientSecret: clientSecret,
          scopes: _getScopes(scopes),
          refreshToken: _identity!.refreshToken!,
          configuration: configuration!,
        ),
      );

      await _completeLogin(response);

      if (autoRefresh) {
        var refreshTime =
            _identity!.expiresAt.difference(DateTime.now().toUtc());
        refreshTime -= const Duration(minutes: 1);

        _autoRenewTimer = Future.delayed(refreshTime, refresh);
      }

      if (raiseEvents) _raiseEvent(const AuthEvent(AuthEventTypes.Refresh));

      return true;
    } on Exception catch (e) {
      clearIdentity();
      _raiseEvent(AuthEvent(AuthEventTypes.Error, message: e.toString()));
      return false;
    } finally {
      _refreshing = false;
    }
  }

  Future<void> clearIdentity() async {
    if (_identity != null) {
      await OpenIdIdentity.clear();
      _identity = null;
    }
  }

  void _raiseEvent(final AuthEvent evt) {
    currentEvent = evt;
    _eventStreamController.sink.add(evt);
  }

  Future<void> _completeLogin(final AuthorizationResponse response) async {
    _identity = OpenIdIdentity.fromAuthorizationResponse(response);

    if (validateAgainstJwksUri) {
      await _setValidatedIdToken(_identity?.idToken);
    }

    await _identity!.save();
  }

  Future<void> _setValidatedIdToken(final String? idToken) async {
    if (idToken == null || keyStore == null) {
      return Future.error(
        "idToken (${idToken == null ? "null" : "not null"})"
        ' or keyStore ($keyStore) is null',
      );
    }
    if (kDebugMode) {
      print('Validating token...');
    }
    return JsonWebToken.decodeAndVerify(idToken, keyStore!).then((final jwt) {
      validatedJWT = jwt;
      if (kDebugMode) {
        print('validatedJWT: ${validatedJWT?.toCompactSerialization()}');
      }
    }).catchError(
      (final dynamic err) {
        if (kDebugMode) {
          print('Error validating idToken: $err');
        }
      },
    );
  }

  Future<bool> _setupAutoRenew() async {
    if (_autoRenewTimer != null) _autoRenewTimer = null;

    if (isTokenAboutToExpire) {
      return await refresh(
          raiseEvents: false); //This will set the timer itself.
    } else {
      var refreshTime = _identity!.expiresAt.difference(DateTime.now().toUtc());

      refreshTime -= const Duration(minutes: 1);

      _autoRenewTimer = Future.delayed(refreshTime, refresh);
      return true;
    }
  }

  Future<void> _verifyDiscoveryDocument() async {
    if (configuration != null) return;

    configuration = await OpenIdConnect.getConfiguration(
      discoveryDocumentUrl,
    );

    final jwksUri = configuration?.jwksUri;
    if (jwksUri == null) {
      return;
    }

    final v = jwksStringsCache[jwksUri];
    final isExpired = !jwksStringsExpiry.containsKey(jwksUri) ||
        (jwksStringsExpiry[jwksUri] ?? 0) <
            DateTime.now().millisecondsSinceEpoch;

    return ((v == null || isExpired)
            ? http.get(Uri.parse(jwksUri)).then((final response) {
                if (response.statusCode != 200) {
                  return;
                }

                jwksStringsCache[jwksUri] = response.body;
                jwksStringsExpiry[jwksUri] = DateTime.now()
                    .add(const Duration(hours: 1))
                    .millisecondsSinceEpoch;
              }).catchError((final dynamic err) {
                if (kDebugMode) {
                  print('ERR! failed to get $jwksUri -> $err');
                }
              })
            : Future<void>.value())
        .whenComplete(() {
      final jwksCache = jwksStringsCache[jwksUri];
      if (jwksCache == null) {
        return Future.value();
      }

      if (kDebugMode) {
        print('decoding $jwksCache...');
      }
      try {
        final jwksMap = jsonDecode(jwksCache) as Map<String, dynamic>;

        if (jwksMap.containsKey('keys')) {
          _keySet = JsonWebKeySet.fromJson(jwksMap);
          if (kDebugMode) {
            print('keyStore: ${_keySet!.keys}');
          }
          keyStore = (keyStore ?? JsonWebKeyStore())..addKeySet(_keySet!);
        }
        return Future.value();
      } catch (err) {
        if (kDebugMode) {
          print('ERR! loading keystore failed: $err');
        }
        jwksStringsCache.remove(jwksUri);
        return Future.error(err);
      }
    });
  }

  ///Gets the proper scopes and adds offline access if the user has it specified in the configuration for the client.
  Iterable<String> _getScopes(final Iterable<String> scopes) {
    if (autoRefresh && !scopes.contains(OFFLINE_ACCESS_SCOPE)) {
      return [OFFLINE_ACCESS_SCOPE, ...scopes];
    }
    return scopes;
  }
}
