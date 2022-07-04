window.SIDEBAR_ITEMS = {"enum":[["Error",""],["InvalidatedTokens","The happy-path result of [InvalidatedJWTsReader::read]."],["MaybeAuthenticated","A “might-be-authenticated” type wrapper."]],"struct":[["AuthenticateMiddleware","The actual middleware that extracts JWTs from requests, validates them, and injects them into a request."],["AuthenticateMiddlewareFactory","A factory for the authentication middleware."],["AuthenticateMiddlewareSettings","Settings for [AuthenticateMiddlewareFactory]. These determine how the authentication middleware will work."],["Authenticated","A “must-be-authenticated” type wrapper, which, when added as a parameter on a route handler, will result in an 401 response if a given request cannot be authenticated."],["ErrorResponse",""],["InvalidatedTokensTag","An opaque tag that can be used in [InvalidatedJWTsReader] implementations for improving the efficiency of periodic reads"],["JWT","A wrapper around JWTs"],["JWTSessionKey","A wrapper to hold the key used for extracting a JWT from an [actix_session::Session]"]],"trait":[["InvalidatedJWTsReader","A reader for invalidated JWTs, for instance from an external shared data store."]]};