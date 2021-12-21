{
  description = "aeiou";

  outputs = { self, nixpkgs }:

    let
      pkgs = nixpkgs.legacyPackages.x86_64-linux;

      rev = "67f103bc8b625f2a4a9e94f1d8c7bd84c5a08d1d";
      hash = "sha256-6MUU2doYt9DaM+6oOVv7hlLF/Ef8eAcdEh/xwzyBNcc=";

      llvmPackages = pkgs.llvmPackages_13;
      llvm = llvmPackages.llvm;
      clang = llvmPackages.clang;
      ld = llvmPackages.lld;
      aflplusplus = (pkgs.aflplusplus.override { clang = clang; llvm = llvm; }).overrideAttrs (oldAttrs: rec {
        inherit llvm;
        inherit clang;

        version = "3.15a-dev";
        doInstallCheck = false;

        src = pkgs.fetchFromGitHub {
          owner = "AFLplusplus";
          repo = "AFLplusplus";
          rev = "74a8f145e09d0361d8f576eb3f2e8881b6116f18";
          sha256 = "1myrqysapixh60sha7y9dzpi3wanz3ragqjdi4yivppcr5rpldxh";
        };

        gcc = pkgs.gcc;
        
        buildInputs = oldAttrs.buildInputs ++ [ ld ];

        postPatch = ''
          # Replace the CLANG_BIN, etc. variables with the correct path
          substituteInPlace src/afl-cc.c \
            --replace "CLANG_BIN" '"${clang}/bin/clang"' \
            --replace "CLANGPP_BIN" '"${clang}/bin/clang++"' \
            --replace 'getenv("AFL_REAL_LD")' "(getenv(\"AFL_REAL_LD\") ? getenv(\"AFL_REAL_LD\") : \"${ld}/bin/ld.lld\")" \
            --replace 'getenv("AFL_PATH")' "(getenv(\"AFL_PATH\") ? getenv(\"AFL_PATH\") : \"$out/lib/afl\")" \
            --replace '"gcc"' '"${gcc}/bin/gcc"' \
            --replace '"g++"' '"${gcc}/bin/g++"' \
            --replace '"gcj"' '"gcj-UNSUPPORTED"' \
            --replace '"clang"' '"clang-UNSUPPORTED"' \
            --replace '"clang++"' '"clang++-UNSUPPORTED"'
        '';

        makeFlags = [ "PREFIX=$(out)" "AFL_REAL_LD=${ld}/bin/ld.lld" ];

        buildPhase = ''
          common="$makeFlags -j$NIX_BUILD_CORES"
          make distrib $common
        '';

        postInstall = ''
          # remove afl-clang(++) which are just symlinks to afl-clang-fast
          rm $out/bin/afl-clang $out/bin/afl-clang++

          # add lto
        '';
      });

      stdenv = pkgs.stdenv;

      cEnvSetup = ''
        export CC=afl-cc CXX=afl-c++ LD=${ld}/bin/ld.lld NIX_CFLAGS_COMPILE="-w -g $NIX_CFLAGS_COMPILE"
        export AFL_LLVM_INSTRUMENT=lto
        export AR=llvm-ar RANLIB=llvm-ranlib
      '';

      mkLottie = { suffix, env }: (
        (stdenv.mkDerivation {

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
            llvmPackages.lld
          ];
          patches = [ ./01-dumb-workaround.patch ];
          configurePhase = ''
            mkdir build;
            cd build;
            ${cEnvSetup} 
            ${env}
            cmake -DBUILD_SHARED_LIBS=off -DLOTTIE_CACHE=off -DLOTTIE_MODULE=off ..
          '';
          buildPhase = ''
            ${cEnvSetup}
            ${env}
            make
          '';
          installPhase = ''
            mkdir -p $out/lib
            cp librlottie.a $out/lib
            mkdir -p $out/include
            cp -r ../inc/* $out/include
          '';
        })
      );
      mkLottieHarness = { suffix, env }:
        let lottie = mkLottie { suffix = suffix; env = env; };
        in
        (stdenv.mkDerivation {
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
            cp harness $out/bin/harness-${suffix}
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
        '';
      };

      rlottie-fuzzer = stdenv.mkDerivation {
        name = "rlottie-fuzzer";

        src = ./.;

        phases = [ "unpackPhase" "installPhase" ];
        buildInputs = [
          aflplusplus
          rlottie-instrumented-asan-harness
          rlottie-instrumented-hardened-harness
          llvm
        ];

        afl_path = "${aflplusplus}";

        installPhase = ''
          mkdir -p $out/resources
          mkdir -p $out/bin

          cp -r ./resources $out

          export fuzz_resources_dir="$out/resources"
          export harness="${rlottie-instrumented-hardened-harness}/bin/harness-instrumented-hardened"

          for f in scripts/*; do substituteAll $f $out/bin/$(basename $f); done

          chmod +x $out/bin/*.sh

          cp ${rlottie-instrumented-asan-harness}/bin/harness-instrumented-asan $out/bin
          cp ${rlottie-instrumented-hardened-harness}/bin/harness-instrumented-hardened $out/bin

          # lol (for asan)
          ln -s ${llvm}/bin/llvm-symbolizer $out/bin
        '';
      };
    in
    {
      packages.x86_64-linux.rlottie-instrumented-hardened-harness = rlottie-instrumented-hardened-harness;
      packages.x86_64-linux.rlottie-instrumented-asan-harness = rlottie-instrumented-asan-harness;
      packages.x86_64-linux.rlottie-fuzzer = rlottie-fuzzer;

      defaultPackage.x86_64-linux = rlottie-fuzzer;

      devShell.x86_64-linux = stdenv.mkDerivation { name = "shell"; buildInputs = [ pkgs.clang rlottie-fuzzer ]; };
    };
}
