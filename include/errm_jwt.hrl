-ifndef(ERRM_JWT_HRL).
-define(ERRM_JWT_HRL, true).

-type alg() :: hs256 | hs384 | hs512 | rs256 | rs384 | rs512 | es256 | es384 | es512.
-type key() :: binary() | {term(), term()}.

-type sign_opts() :: #{
  ttl => non_neg_integer(),
  iat => integer(),
  nbf => integer(),
  exp => integer(),
  jti => binary(),
  kid => binary(),
  header => map()
}.

-type verify_opts() :: #{
  leeway => non_neg_integer(),
  audience => binary() | [binary()],
  issuer => binary(),
  subject => binary(),
  required_claims => [binary()]
}.

-type token() :: binary().
-type header() :: map().
-type claims() :: map().

-define(DEFAULT_LEEWAY, 60).
-define(DEFAULT_TTL, 3600).

-endif.
