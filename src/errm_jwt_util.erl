-module(errm_jwt_util).
-export([now/0, to_binary/1, ensure_map/1]).

now() -> erlang:system_time(second).

to_binary(S) when is_list(S) -> list_to_binary(S);
to_binary(S) when is_atom(S) -> atom_to_binary(S, utf8);
to_binary(S) -> S.

-spec ensure_map(term()) -> map().
ensure_map(Term) when is_map(Term) -> Term;
ensure_map(Term) -> error({invalid_json_type, Term}).
