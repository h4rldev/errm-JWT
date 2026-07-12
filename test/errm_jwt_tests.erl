-module(errm_jwt_tests).
-include_lib("eunit/include/eunit.hrl").
-include("include/errm_jwt.hrl").

-define(SECRET, <<"my-very-secret-key">>).

setup_rsa_keys() ->
  {RsaPub, RsaPriv} = crypto:generate_key(rsa, {2048, 65537}),
  {RsaPriv, RsaPub}.

setup_ec_keys() ->
  {EcPub, EcPriv} = crypto:generate_key(ecdh, secp256r1),
  {EcPriv, EcPub}.

hmac_test_() ->
    {setup,
     fun() -> ok end,
     fun(_) -> ok end,
     [fun test_hmac_sign_verify/0,
      fun test_hmac_expired/0,
      fun test_hmac_algorithm_mismatch/0]}.

test_hmac_sign_verify() ->
  Claims = #{<<"sub">> => <<"123">>, <<"name">> => <<"Alice">>},
  {ok, Token} = errm_jwt:sign(Claims, ?SECRET, hs256),
  {ok, Decoded} = errm_jwt:verify(Token, ?SECRET, hs256),
  ?assertMatch(#{
    <<"iat">> := _,
    <<"exp">> := _,
    <<"nbf">> := _,
    <<"jti">> := _,
    <<"sub">> := <<"123">>,
    <<"name">> := <<"Alice">>
  }, Decoded).

test_hmac_expired() ->
    Claims = #{<<"sub">> => <<"expired">>, <<"exp">> => errm_jwt_util:now() - 10},
    {ok, Token} = errm_jwt:sign(Claims, ?SECRET, hs256),
    {error, expired} = errm_jwt:verify(Token, ?SECRET, hs256, #{leeway => 0}),
    ok.

test_hmac_algorithm_mismatch() ->
  {ok, Token} = errm_jwt:sign(#{}, ?SECRET, hs256),
  {error, algorithm_mismatch} = errm_jwt:verify(Token, ?SECRET, hs384),
  ok.

rsa_test_() ->
  {setup,
    fun() -> setup_rsa_keys() end,
    fun(_) -> ok end,
    {with, [fun test_rsa_sign_verify/1,
            fun test_rsa_invalid_signature/1]}}.
test_rsa_sign_verify({Priv, Pub}) ->
  Claims = #{<<"sub">> => <<"rsa">>},
  {ok, Token} = errm_jwt:sign(Claims, {Priv, Pub}, rs256),
  {ok, Decoded} = errm_jwt:verify(Token, {Priv, Pub}, rs256),
  ?assertMatch(#{
    <<"iat">> := _,
    <<"exp">> := _,
    <<"nbf">> := _,
    <<"jti">> := _,
    <<"sub">> := <<"rsa">>
  }, Decoded).

test_rsa_invalid_signature({Priv, Pub}) ->
  Claims = #{<<"sub">> => <<"rsa">>},
  {ok, Token} = errm_jwt:sign(Claims, {Priv, Pub}, rs256),
  [H, P, _] = binary:split(Token, <<".">>, [global]),
  Tampered = <<H/binary, ".", P/binary, ".", (base64:encode(<<"x">>, #{mode => 'urlsafe', padding => false}))/binary>>,
  {error, invalid_signature} = errm_jwt:verify(Tampered, {Priv, Pub}, rs256),
  ok.

ecdsa_test_() ->
  {setup,
    fun() -> setup_ec_keys() end,
    fun(_) -> ok end,
    {with, [fun test_ecdsa_sign_verify/1]}}.

test_ecdsa_sign_verify({Priv, Pub}) ->
  Claims = #{<<"sub">> => <<"ec">>},
  {ok, Token} = errm_jwt:sign(Claims, {Priv, Pub}, es256),
  {ok, Decoded} = errm_jwt:verify(Token, {Priv, Pub}, es256),
  ?assertMatch(#{
    <<"iat">> := _,
    <<"exp">> := _,
    <<"nbf">> := _,
    <<"jti">> := _,
    <<"sub">> := <<"ec">>
  }, Decoded).

claims_test_() ->
    [fun() -> test_claims_add_standard() end,
     fun() -> test_claims_audience() end,
     fun() -> test_claims_issuer() end,
     fun() -> test_claims_subject() end,
     fun() -> test_claims_required() end,
     fun() -> test_claims_leeway() end].

test_claims_add_standard() ->
  Now = errm_jwt_util:now(),
  {ok, Token} = errm_jwt:sign(#{}, ?SECRET, hs256, #{ttl => 60}),
  {ok, Claims} = errm_jwt:verify(Token, ?SECRET, hs256),
  ?assertEqual(maps:get(<<"iat">>, Claims, 0), Now),
  ?assertEqual(maps:get(<<"exp">>, Claims, 0), Now + 60),
  ?assertEqual(maps:get(<<"nbf">>, Claims, 0), Now),
  ?assert(is_binary(maps:get(<<"jti">>, Claims, undefined))).

test_claims_audience() ->
  Claims = #{<<"aud">> => <<"myapp">>},
  {ok, Token} = errm_jwt:sign(Claims, ?SECRET, hs256),
  {ok, _} = errm_jwt:verify(Token, ?SECRET, hs256, #{audience => <<"myapp">>}),
  {error, invalid_audience} = errm_jwt:verify(Token, ?SECRET, hs256, #{audience => <<"otherapp">>}),
  ok.

test_claims_issuer() ->
  Claims = #{<<"iss">> => <<"auth.example.com">>},
  {ok, Token} = errm_jwt:sign(Claims, ?SECRET, hs256),
  {ok, _} = errm_jwt:verify(Token, ?SECRET, hs256, #{issuer => <<"auth.example.com">>}),
  {error, invalid_issuer} = errm_jwt:verify(Token, ?SECRET, hs256, #{issuer => <<"wrong">>}),
  ok.

test_claims_subject() ->
  Claims = #{<<"sub">> => <<"user123">>},
  {ok, Token} = errm_jwt:sign(Claims, ?SECRET, hs256),
  {ok, _} = errm_jwt:verify(Token, ?SECRET, hs256, #{subject => <<"user123">>}),
  {error, invalid_subject} = errm_jwt:verify(Token, ?SECRET, hs256, #{subject => <<"wrong">>}),
  ok.

test_claims_required() ->
  Claims = #{<<"sub">> => <<"user">>, <<"role">> => <<"admin">>},
  {ok, Token} = errm_jwt:sign(Claims, ?SECRET, hs256),
  {ok, _} = errm_jwt:verify(Token, ?SECRET, hs256, #{required_claims => [<<"sub">>, <<"role">>]}),
  {error, {missing_required, <<"extra">>}} =
    errm_jwt:verify(Token, ?SECRET, hs256, #{required_claims => [<<"sub">>, <<"role">>, <<"extra">>]}),
  ok.

test_claims_leeway() ->
  Now = errm_jwt_util:now(),
  Claims = #{<<"exp">> => Now + 5},
  {ok, Token} = errm_jwt:sign(Claims, ?SECRET, hs256),
  {ok, _} = errm_jwt:verify(Token, ?SECRET, hs256),
  ClaimsExpired = #{<<"exp">> => Now - 10},
  {ok, TokenExp} = errm_jwt:sign(ClaimsExpired, ?SECRET, hs256),
  {ok, _} = errm_jwt:verify(TokenExp, ?SECRET, hs256, #{leeway => 30}),  %% 10 < 30, so ok
  {error, expired} = errm_jwt:verify(TokenExp, ?SECRET, hs256, #{leeway => 5}),
  ok.

malformed_test() ->
  {error, malformed_token} = errm_jwt:verify(<<"bad.token">>, ?SECRET, hs256),
  ok.
