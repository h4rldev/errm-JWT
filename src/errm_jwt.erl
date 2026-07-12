-module(errm_jwt).
-export([sign/3, sign/4, verify/3, verify/4]).
-export([decode_header/1, decode_payload/1]).
-export([alg_to_string/1]).
-include("include/errm_jwt.hrl").
-export_type([alg/0, key/0, sign_opts/0, verify_opts/0, token/0, header/0, claims/0]).

-spec sign(Claims :: claims(), Key :: key(), Alg :: alg()) -> {ok, JWT :: binary()} | {error, Reason :: term()}.
sign(Claims, Key, Alg) ->
  sign(Claims, Key, Alg, #{}).

-spec sign(Claims :: claims(), Key :: key(), Alg :: alg(), Opts :: sign_opts()) -> {ok, JWT :: binary()} | {error, Reason :: term()}.
sign(Claims, Key, Alg, Opts) ->
  try
    Claims1 = errm_jwt_claims:add_standard(Claims, Opts),

    HeaderMap = maps:get(header, Opts, #{}),
    Header0 = HeaderMap#{
      <<"alg">> => alg_to_string(Alg),
      <<"typ">> => <<"JWT">>
    },
    Header = case maps:get(kid, Opts, undefined) of
      undefined -> Header0;
      Kid -> Header0#{<<"kid">> => Kid}
    end,

    HeaderJson = errm_json:encode(Header),
    HeaderBin = iolist_to_binary(HeaderJson),
    HeaderB64 = base64:encode(HeaderBin, #{mode => 'urlsafe', padding => false}),

    PayloadJson = errm_json:encode(Claims1),
    PayloadBin = iolist_to_binary(PayloadJson),
    PayloadB64 = base64:encode(PayloadBin, #{mode => 'urlsafe', padding => false}),

    SigningInput = <<HeaderB64/binary, ".", PayloadB64/binary>>,
    Sig = errm_jwt_signer:sign(SigningInput, Key, Alg),

    SigB64 = base64:encode(Sig, #{mode => 'urlsafe', padding => false}),
    {ok, <<SigningInput/binary, ".", SigB64/binary>>}
  catch
    Class:Reason:Stacktrace ->
      {error, {Class, Reason, Stacktrace}}
  end.

-spec verify(JWT :: binary(), Key :: key(), Alg :: alg()) -> {ok, Claims :: map()} | {error, Reason :: term()}.
verify(JWT, Key, Alg) ->
  verify(JWT, Key, Alg, #{}).

-spec verify(JWT :: binary(), Key :: key(), Alg :: alg(), Opts :: verify_opts()) -> {ok, map()} | {error, term()}.
verify(JWT, Key, Alg, Opts) ->
  Parts = binary:split(JWT, <<".">>, [global]),
  case Parts of
    [HeaderB64, PayloadB64, SigB64] ->
      HeaderBin = base64:decode(HeaderB64, #{mode => 'urlsafe', padding => false}),
      PayloadBin = base64:decode(PayloadB64, #{mode => 'urlsafe', padding => false}),
      SigBin = base64:decode(SigB64, #{mode => 'urlsafe', padding => false}),

      case errm_json:decode(HeaderBin) of
        {ok, HeaderTerm} ->
          HeaderMap = errm_jwt_util:ensure_map(HeaderTerm),
          case maps:get(<<"alg">>, HeaderMap, undefined) of
            AlgString when is_binary(AlgString) ->
              Expected = alg_to_string(Alg),
              case AlgString =:= Expected of
                true ->
                  SigningInput = <<HeaderB64/binary, ".", PayloadB64/binary>>,
                  case errm_jwt_signer:verify(SigningInput, SigBin, Key, Alg) of
                    true ->
                      case errm_json:decode(PayloadBin) of
                        {ok, ClaimsTerm} ->
                          ClaimsMap = errm_jwt_util:ensure_map(ClaimsTerm),
                          errm_jwt_claims:validate(ClaimsMap, Opts);
                        {error, Reason} ->
                          {error, {payload_decode_error, Reason}}
                      end;
                    false ->
                      {error, invalid_signature}
                  end;
                false ->
                  {error, algorithm_mismatch}
              end;
            _ ->
              {error, missing_alg}
          end;
        {error, Reason} ->
          {error, {header_decode_error, Reason}}
      end;
    _ ->
      {error, malformed_token}
  end.

decode_header(JWT) ->
  [HeaderB64 | _] = binary:split(JWT, <<".">>, [global]),
  HeaderBin = base64:decode(HeaderB64, #{mode => 'urlsafe', padding => false}),
  errm_json:decode(HeaderBin).

decode_payload(JWT) ->
  [_, PayloadB64 | _] = binary:split(JWT, <<".">>, [global]),
  PayloadBin = base64:decode(PayloadB64, #{mode => 'urlsafe', padding => false}),
  errm_json:decode(PayloadBin).

-spec alg_to_string(alg()) -> binary().
alg_to_string(hs256) -> <<"HS256">>;
alg_to_string(hs384) -> <<"HS384">>;
alg_to_string(hs512) -> <<"HS512">>;
alg_to_string(rs256) -> <<"RS256">>;
alg_to_string(rs384) -> <<"RS384">>;
alg_to_string(rs512) -> <<"RS512">>;
alg_to_string(es256) -> <<"ES256">>;
alg_to_string(es384) -> <<"ES384">>;
alg_to_string(es512) -> <<"ES512">>.
