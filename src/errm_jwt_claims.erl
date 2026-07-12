-module(errm_jwt_claims).
-export([add_standard/2, validate/2]).
-include("include/errm_jwt.hrl").

-spec add_standard(Claims :: claims(), Opts :: sign_opts()) -> Claims :: claims().
add_standard(Claims, Opts) ->
  Now = errm_jwt_util:now(),
  TTL = maps:get(ttl, Opts, ?DEFAULT_TTL),
  C1 = ensure(Claims, <<"iat">>, maps:get(iat, Opts, Now)),
  C2 = ensure(C1, <<"exp">>, maps:get(exp, Opts, Now + TTL)),
  C3 = ensure(C2, <<"nbf">>, maps:get(nbf, Opts, Now)),
  DefaultJti = errm_uuid:to_string(errm_uuid:v4()),
  ensure(C3, <<"jti">>, maps:get(jti, Opts, DefaultJti)).

-spec ensure(Map :: map(), Key :: key(), Value :: term()) -> Map :: map().
ensure(Map, Key, Value) ->
  case maps:is_key(Key, Map) of
    true -> Map;
    false -> Map#{Key => Value}
  end.

-spec validate(Claims :: claims(), Opts :: verify_opts()) -> {ok, Claims :: claims()} | {error, Reason :: term()}.
validate(Claims, Opts) ->
  try
    Leeway = maps:get(leeway, Opts, ?DEFAULT_LEEWAY),
    Now = errm_jwt_util:now(),
    validate_exp(Claims, Now, Leeway),
    validate_nbf(Claims, Now, Leeway),
    validate_audience(Claims, Opts),
    validate_issuer(Claims, Opts),
    validate_subject(Claims, Opts),
    validate_required(Claims, Opts),
    {ok, Claims}
  catch
    {error, Reason} -> {error, Reason}
  end.

validate_exp(Claims, Now, Leeway) ->
  case maps:get(<<"exp">>, Claims, undefined) of
    undefined -> throw({error, missing_exp});
    Exp when Exp < Now - Leeway -> throw({error, expired});
    _ -> ok
  end.

validate_nbf(Claims, Now, Leeway) ->
  case maps:get(<<"nbf">>, Claims, undefined) of
    undefined -> ok;
    Nbf when Nbf > Now + Leeway -> throw({error, not_valid_yet});
    _ -> ok
  end.

validate_audience(Claims, Opts) ->
  case maps:get(audience, Opts, undefined) of
    undefined -> ok;
    Expected when is_binary(Expected) ->
      case maps:get(<<"aud">>, Claims, undefined) of
        Expected -> ok;
        _ -> throw({error, invalid_audience})
      end;
    ExpectedList when is_list(ExpectedList) ->
      case maps:get(<<"aud">>, Claims, undefined) of
        Aud when is_binary(Aud) ->
          case lists:member(Aud, ExpectedList) of
            true -> ok;
            false -> throw({error, invalid_audience})
          end;
        _ -> throw({error, invalid_audience})
      end
  end.

validate_issuer(Claims, Opts) ->
  case maps:get(issuer, Opts, undefined) of
    undefined -> ok;
    Expected ->
      case maps:get(<<"iss">>, Claims, undefined) of
        Expected -> ok;
        _ -> throw({error, invalid_issuer})
      end
  end.

validate_subject(Claims, Opts) ->
  case maps:get(subject, Opts, undefined) of
    undefined -> ok;
    Expected ->
      case maps:get(<<"sub">>, Claims, undefined) of
        Expected -> ok;
        _ -> throw({error, invalid_subject})
      end
  end.

validate_required(Claims, Opts) ->
  Required = maps:get(required_claims, Opts, []),
  lists:foreach(fun(Key) ->
    case maps:is_key(Key, Claims) of
      true -> ok;
      false -> throw({error, {missing_required, Key}})
    end
  end, Required),
  ok.
