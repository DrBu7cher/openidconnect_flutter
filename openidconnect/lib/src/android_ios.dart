part of openidconnect;

class OpenIdConnectAndroidiOS {
  static Future<String> authorizeInteractive({
    required BuildContext context,
    required String title,
    required String authorizationUrl,
    required String redirectUrl,
    required double popupWidth,
    required double popupHeight,
    Color? backgroundColor,
    bool inBackground = false,
    Future<flutterWebView.NavigationDecision?> Function(
            BuildContext, flutterWebView.NavigationRequest)?
        navigationInterceptor,
  }) async {
    final controller = WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..enableZoom(false);

    if (controller.platform is flutterWkWebView.WebKitWebViewController) {
      (controller.platform as flutterWkWebView.WebKitWebViewController)
          .setAllowsBackForwardNavigationGestures(true);
    }

    //Create the url
    final result = await showDialog<String?>(
      context: context,
      barrierDismissible: false,
      builder: (dialogContext) {
        return AlertDialog(
          insetPadding: EdgeInsets.zero,
          titlePadding: EdgeInsets.zero,
          contentPadding: EdgeInsets.zero,
          actionsPadding: EdgeInsets.zero,
          content: WillPopScope(
            // Catched back button pressed
            onWillPop: () async {
              if (await controller.canGoBack()) {
                await controller.goBack();
                return false;
              }
              return true;
            },
            child: Stack(
              children: [
                Container(
                  width: min(
                      popupWidth.toDouble(), MediaQuery.of(context).size.width),
                  height: min(popupHeight.toDouble(),
                      MediaQuery.of(context).size.height),
                  child: flutterWebView.WebViewWidget(
                    controller: controller
                      ..setNavigationDelegate(NavigationDelegate(
                        onNavigationRequest: (navigation) async {
                          if (navigationInterceptor != null) {
                            var interceptionResult = await navigationInterceptor
                                .call(context, navigation);

                            if (interceptionResult != null)
                              return interceptionResult;
                          }
                          return flutterWebView.NavigationDecision.navigate;
                        },
                        onPageFinished: (url) {
                          if (url.startsWith(redirectUrl)) {
                            Navigator.pop(dialogContext, url);
                          }
                        },
                      ))
                      ..loadRequest(
                        Uri.parse(authorizationUrl),
                      ),
                  ),
                ),
                Positioned(
                  top: 0,
                  left: 0,
                  child: Container(
                    decoration: BoxDecoration(
                        color: Colors.white24,
                        borderRadius: BorderRadius.only(
                            bottomRight: Radius.circular(20))),
                    child: IconButton(
                      onPressed: () => Navigator.pop(dialogContext, null),
                      icon: Icon(Icons.close),
                    ),
                  ),
                )
              ],
            ),
          ),
        );
      },
    );

    if (result == null) throw AuthenticationException(ERROR_USER_CLOSED);

    return result;
  }
}
