-module(errm_jwt_demo).
-export([main/1]).

main(_Args) ->
  io:format("=== errm_jwt interactive demo ===~n~n"),
  scene_hmac(),
  scene_rsa(),
  scene_ec(),
  scene_decode(),
  scene_validation(),
  io:format("~n=== done ===~n"),
  ok.

scene_hmac() ->
  io:format("--- Scene 1: HMAC (HS256) ---~n"),
  Secret = <<"my-shared-secret">>,

  Claims = #{
    <<"sub">>   => <<"alice@example.com">>,
    <<"name">>  => <<"Alice">>,
    <<"roles">> => [<<"admin">>, <<"editor">>]
  },

  {ok, JWT} = errm_jwt:sign(Claims, Secret, hs256),
  io:format("  Signed JWT:~n  ~s~n~n", [JWT]),

  {ok, Verified} = errm_jwt:verify(JWT, Secret, hs256),
  io:format("  Verified claims:~n  ~p~n~n", [Verified]),
  ok.

scene_rsa() ->
  io:format("--- Scene 2: RSA (RS256) ---~n"),
  {Pub, Priv} = crypto:generate_key(rsa, {2048, 65537}),
  KeyPair = {Priv, Pub},

  Claims = #{
    <<"sub">>   => <<"bob@example.com">>,
    <<"department">> => <<"engineering">>
  },

  {ok, JWT} = errm_jwt:sign(Claims, KeyPair, rs256, #{
    kid => <<"rsa-key-2024">>,
    ttl => 7200
  }),
  io:format("  Signed JWT (first 80 chars):~n  ~s...~n", [slice(JWT, 80)]),

  {ok, Verified} = errm_jwt:verify(JWT, KeyPair, rs256),
  io:format("  sub: ~s~n", [maps:get(<<"sub">>, Verified)]),
  io:format("  exp: ~w (TTL was 7200s)~n~n", [maps:get(<<"exp">>, Verified)]),
  ok.

scene_ec() ->
  io:format("--- Scene 3: ECDSA (ES256) ---~n"),
  {Pub, Priv} = crypto:generate_key(ecdh, secp256r1),
  KeyPair = {Priv, Pub},

  Claims = #{
    <<"sub">>    => <<"carol@example.com">>,
    <<"premium">> => true
  },

  {ok, JWT} = errm_jwt:sign(Claims, KeyPair, es256),
  io:format("  Signed JWT (first 80 chars):~n  ~s...~n", [slice(JWT, 80)]),

  {ok, Verified} = errm_jwt:verify(JWT, KeyPair, es256),
  io:format("  sub: ~s~n", [maps:get(<<"sub">>, Verified)]),
  io:format("  premium: ~w~n~n", [maps:get(<<"premium">>, Verified)]),
  ok.

scene_decode() ->
  io:format("--- Scene 4: Decode (no verification) ---~n"),
  Secret = <<"inspect-me">>,

  {ok, JWT} = errm_jwt:sign(#{<<"sub">> => <<"dave">>}, Secret, hs384, #{
    kid => <<"key-1">>
  }),

  {ok, Header} = errm_jwt:decode_header(JWT),
  io:format("  Header: ~p~n", [Header]),

  {ok, Payload} = errm_jwt:decode_payload(JWT),
  io:format("  Payload: ~p~n~n", [Payload]),
  ok.

scene_validation() ->
  io:format("--- Scene 5: Validation options ---~n"),
  Secret = <<"validation-secret">>,

  Claims = #{
    <<"sub">> => <<"eve">>,
    <<"iss">> => <<"https://auth.example.com">>,
    <<"aud">> => <<"api.example.com">>,
    <<"scope">> => <<"read:posts write:posts">>
  },

  {ok, JWT} = errm_jwt:sign(Claims, Secret, hs256),

  %% Verify with audience, issuer, and required claim constraints
  {ok, Verified} = errm_jwt:verify(JWT, Secret, hs256, #{
    audience => <<"api.example.com">>,
    issuer   => <<"https://auth.example.com">>,
    required_claims => [<<"sub">>, <<"scope">>]
  }),

  io:format("  All validations passed!~n"),
  io:format("  sub:   ~s~n", [maps:get(<<"sub">>, Verified)]),
  io:format("  iss:   ~s~n", [maps:get(<<"iss">>, Verified)]),
  io:format("  aud:   ~s~n", [maps:get(<<"aud">>, Verified)]),
  io:format("  scope: ~s~n~n", [maps:get(<<"scope">>, Verified)]),
  ok.

slice(Bin, N) when byte_size(Bin) =< N -> Bin;
slice(Bin, N) -> binary:part(Bin, 0, N).% Set exp far in the past

