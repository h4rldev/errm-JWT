{
  description = "Errm.. JWT, an implementation of Json Web Tokens for Erlang";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    errm-json.url = "github:h4rldev/errm-JSON";
    errm-uuid.url = "github:h4rldev/errm-UUID";
  };

  outputs = {
    self,
    nixpkgs,
    errm-json,
    errm-uuid,
  }: let
    system = "x86_64-linux";
    pkgs = import nixpkgs {inherit system;};
    beamPackages = pkgs.beamPackages;
    myDeps = [
      errm-json.packages.${system}.default
      errm-uuid.packages.${system}.default
      errm-json.packages.${system}.errm-json-debug
      errm-uuid.packages.${system}.errm-uuid-debug
    ];

    errm-prod = beamPackages.buildRebar3 {
      name = "errm-JWT";
      version = "0.1.0-prod";

      src = ./.;

      beamDeps = [
        errm-json.packages.${system}.default
        errm-uuid.packages.${system}.default
      ];

      env = {
        REBAR_PROFILE = "prod";
      };
    };

    errm-debug = beamPackages.buildRebar3 {
      name = "errm-JWT";
      version = "0.1.0-debug";

      src = ./.;

      beamDeps = [
        errm-json.packages.${system}.errm-json-debug
        errm-uuid.packages.${system}.errm-uuid-debug
      ];

      env = {
        REBAR_PROFILE = "debug";
      };
    };
  in {
    packages.${system} = {
      errm-jwt-prod = errm-prod;
      default = errm-prod;
      errm-jwt-debug = errm-debug;
    };

    devShells.${system}.default = pkgs.mkShell {
      name = "errm-JWT";

      buildInputs = with pkgs; [
        beamPackages.erlang
        beamPackages.rebar3
      ];

      packages = with pkgs; [
        erlang-language-platform
      ];

      shellHook = ''
        mkdir -p _checkouts
        ${builtins.concatStringsSep "\n" (map (dep: ''
            for app in ${dep}/lib/erlang/lib/*; do
              ln -sfn "$app" _checkouts/$(basename "$app")
            done
          '')
          myDeps)}
      '';
    };
  };
}
