{
  outputs = { nixpkgs, ... }: {
    nixopsConfigurations.default = import nixops/nixops.nix {
      inherit nixpkgs;
    };
  };
}
