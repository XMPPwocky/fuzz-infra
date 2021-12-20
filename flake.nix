{
  inputs = {
    fuzzers.url = "path:./fuzzers";
  };
  outputs = { nixpkgs, fuzzers, ... }: {
    nixopsConfigurations.default = import nixops/nixops.nix {
      inherit nixpkgs;
      fuzzerPkgs = fuzzers.packages.x86_64-linux;
    };
  };
}


