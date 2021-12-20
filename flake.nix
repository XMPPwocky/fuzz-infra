{
  outputs = { nixpkgs, ... }: (
    {
      nixopsConfigurations.default = {
        inherit nixpkgs;

        network.description = "fuzzing";
        network.storage.legacy = {
          databasefile = "~/.nixops/deployments.nixops";
        };

        fuzz1 = import ./simple-fuzz.nix;

      };
    }
  );
}
