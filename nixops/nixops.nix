{ nixpkgs, ... }:
let mkFuzzer = import ./simple-fuzz.nix; in
{ fuzzers ? { } }: {
  inherit nixpkgs;

  network.description = "fuzzing";
  network.storage.legacy = {
    databasefile = "~/.nixops/deployments.nixops";
  };

} // (builtins.trace fuzzers (builtins.mapAttrs (name: value: (mkFuzzer name value)) fuzzers))
