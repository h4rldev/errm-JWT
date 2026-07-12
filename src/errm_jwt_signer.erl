-module(errm_jwt_signer).
-export([sign/3, verify/4]).

sign(Data, Key, hs256) -> crypto:mac(hmac, sha256, Key, Data);
sign(Data, Key, hs384) -> crypto:mac(hmac, sha384, Key, Data);
sign(Data, Key, hs512) -> crypto:mac(hmac, sha512, Key, Data);

sign(Data, {Priv, _}, rs256) -> crypto:sign(rsa, sha256, Data, Priv);
sign(Data, {Priv, _}, rs384) -> crypto:sign(rsa, sha384, Data, Priv);
sign(Data, {Priv, _}, rs512) -> crypto:sign(rsa, sha512, Data, Priv);

sign(Data, {Priv, _}, es256) -> crypto:sign(ecdsa, sha256, Data, [Priv, secp256r1]);
sign(Data, {Priv, _}, es384) -> crypto:sign(ecdsa, sha384, Data, [Priv, secp384r1]);
sign(Data, {Priv, _}, es512) -> crypto:sign(ecdsa, sha512, Data, [Priv, secp521r1]).

%% HMAC — unchanged
verify(Data, Sig, Key, hs256) -> crypto:mac(hmac, sha256, Key, Data) =:= Sig;
verify(Data, Sig, Key, hs384) -> crypto:mac(hmac, sha384, Key, Data) =:= Sig;
verify(Data, Sig, Key, hs512) -> crypto:mac(hmac, sha512, Key, Data) =:= Sig;

verify(Data, Sig, {_, Pub}, rs256) -> crypto:verify(rsa, sha256, Data, Sig, Pub);
verify(Data, Sig, {_, Pub}, rs384) -> crypto:verify(rsa, sha384, Data, Sig, Pub);
verify(Data, Sig, {_, Pub}, rs512) -> crypto:verify(rsa, sha512, Data, Sig, Pub);

verify(Data, Sig, {_, Pub}, es256) -> crypto:verify(ecdsa, sha256, Data, Sig, [Pub, secp256r1]);
verify(Data, Sig, {_, Pub}, es384) -> crypto:verify(ecdsa, sha384, Data, Sig, [Pub, secp384r1]);
verify(Data, Sig, {_, Pub}, es512) -> crypto:verify(ecdsa, sha512, Data, Sig, [Pub, secp521r1]).
