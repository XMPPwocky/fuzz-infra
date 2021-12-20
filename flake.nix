{
  outputs = { nixpkgs }: (
  {
    nixopsConfigurations.default = {
      inherit nixpkgs;

      network.description = "fuzzing";
      fuzz1 = import ./simple-fuzz.nix;

    };
  }
  );
}
