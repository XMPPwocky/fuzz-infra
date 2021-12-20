{
  description = "A very basic flake";

  outputs = { self, nixpkgs }:

    let
      pkgs = nixpkgs.legacyPackages.x86_64-linux;

      rev = "67f103bc8b625f2a4a9e94f1d8c7bd84c5a08d1d";
      hash = "sha256-6MUU2doYt9DaM+6oOVv7hlLF/Ef8eAcdEh/xwzyBNcc=";

      aflplusplus = pkgs.aflplusplus;
      aflStdenv = pkgs.overrideCC pkgs.stdenv aflplusplus;

      cEnvSetup = ''
        export CC=afl-clang-fast CXX=afl-clang-fast++ NIX_CFLAGS_COMPILE="-w -g $NIX_CFLAGS_COMPILE"
      '';

      mkLottie = { suffix, env }: ((pkgs.stdenv.mkDerivation {
        dontStrip = true;

        pname = "rlottie-${suffix}";
        version = "git-${rev}";
        src = pkgs.fetchFromGitHub {
          owner = "TelegramMessenger";
          repo = "rlottie";
          rev = rev;
          hash = hash;
        };
        nativeBuildInputs = [ aflplusplus ];
        buildInputs = [
          pkgs.cmake
        ];
        configurePhase = ''
          mkdir build;
          cd build;
          ${cEnvSetup} 
          ${env}
          cmake ..
        '';
        buildPhase = ''
          ${cEnvSetup}
          ${env}
          make
        '';
        installPhase = ''
          mkdir -p $out/lib
          cp librlottie.so* $out/lib
          mkdir -p $out/include
          cp -r ../inc/* $out/include
        '';
      }));
      mkLottieHarness = { suffix, env }: let lottie = mkLottie { suffix = suffix; env = env; };
      in (aflStdenv.mkDerivation {
        dontStrip = true;

        pname = "rlottie-harness-${suffix}";
        version = "0.1.0";
        src = ./src;
        nativeBuildInputs = [ aflplusplus ];
        buildInputs = [ lottie ];
        buildPhase = ''
          ${cEnvSetup}
          ${env}
          LOTTIE_DIR="${lottie}" make
        '';
        installPhase = ''
          mkdir -p $out/bin
          cp harness $out/bin
        '';
      });

      rlottie-instrumented-hardened-harness = mkLottieHarness {
        suffix = "instrumented-hardened";
        env = ''
          export AFL_HARDEN="1";
        '';
      };
      rlottie-instrumented-asan-harness = mkLottieHarness {
        suffix = "instrumented-asan";
        env = ''
          export AFL_USE_ASAN="1";
          export AFL_USE_CFISAN="1";
        '';
      };

    in
    {
      packages.x86_64-linux.rlottie-instrumented-hardened-harness = rlottie-instrumented-hardened-harness;
      packages.x86_64-linux.rlottie-instrumented-asan-harness = rlottie-instrumented-asan-harness;
      devShell.x86_64-linux = aflStdenv.mkDerivation { name = "shell"; buildInputs = [ pkgs.clang ];};
    };
}