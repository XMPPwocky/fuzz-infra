{
  inputs = {
    rlottie.url = "path:./rlottie";
  };
  outputs = { nixpkgs, rlottie, ... }: {
    packages = rlottie.packages;
  };
}
