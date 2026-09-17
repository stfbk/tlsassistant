{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";

    tls-compliance-dataset = {
      url = "github:stfbk/tls-compliance-dataset?ref=ACN"; # TODO: change post-release
      flake = false;
    };
    testssl = {
      url = "github:testssl/testssl.sh";
      flake = false;
    };
    tls-table = {
      url = "github:mozilla/tls-table";
      flake = false;
    };
    dhe-groups = {
      url = "github:internetstandards/dhe_groups";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, tls-compliance-dataset
            , testssl, tls-table, dhe-groups }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          config.permittedInsecurePackages = [
            "python3.12-ecdsa-0.19.2"
          ];
        };

        pythonPackages = pkgs.python312Packages;

        apacheconfig = pythonPackages.buildPythonPackage rec {
          pname = "apacheconfig";
          version = "0.3.2";
          pyproject = true;
          src = pkgs.fetchPypi {
            inherit pname version;
            hash = "sha256-xTIE83uwEM/YjQXWXvV5tGJ6p2yOxttyYkO8Y9yQu3A=";
          };
          build-system = [ pythonPackages.setuptools ];
          propagatedBuildInputs = with pythonPackages; [ ply six ];
          doCheck = false;
        };

        z3c-rml = pythonPackages.buildPythonPackage rec {
          pname = "z3c.rml";
          version = "5.2";
          format = "wheel";
          src = pkgs.fetchurl {
            url = "https://files.pythonhosted.org/packages/py3/z/z3c_rml/z3c_rml-${version}-py3-none-any.whl";
            hash = "sha256-+ciXuJkmPIRx3ChY8q95EmIWn18JRIXPfGa24mX45h4=";
          };
          propagatedBuildInputs = with pythonPackages; [
            pygments
            lxml
            pikepdf
            reportlab
            svglib
            zope-interface
            zope-schema
          ];
          doCheck = false;
        };

        pythonEnv = pkgs.python312.withPackages (ps: with ps; [
          aiohttp
          apacheconfig
          async-timeout
          beautifulsoup4
          crossplane
          cryptography
          idna
          jinja2
          jsonmerge
          markdown2
          marshmallow
          marshmallow-dataclass
          pebble
          pyasn1
          pyopenssl
          python-dateutil
          requests
          setuptools
          stix2
          stix2-patterns
          tldextract
          tlslite-ng
          yapsy
          z3c-rml
        ]);

        # TODO: this has to be changed post-release
        requirementsDb = pkgs.stdenvNoCC.mkDerivation {
          name = "tls-compliance-dataset-db";
          src = tls-compliance-dataset;
          nativeBuildInputs = [
            (pkgs.python312.withPackages (ps: with ps; [
              pandas
              openpyxl
            ]))
            pkgs.prisma_6
            pkgs.prisma-engines_6
          ];
          buildPhase = ''
            export HOME=$TMPDIR
            export PRISMA_SCHEMA_ENGINE_BINARY="${pkgs.prisma-engines_6}/bin/schema-engine"
            export PRISMA_QUERY_ENGINE_BINARY="${pkgs.prisma-engines_6}/bin/query-engine"
            export PRISMA_QUERY_ENGINE_LIBRARY="${pkgs.prisma-engines_6}/lib/libquery_engine.node"
            export PRISMA_FMT_BINARY="${pkgs.prisma-engines_6}/bin/prisma-fmt"

            python3 schema_creator.py
            python3 database_filler.py
          '';
          installPhase = ''
            mkdir -p $out
            cp requirements.db $out/
            cp utils/default_versions.json $out/
          '';
        };

        roboto-fonts = pkgs.fetchzip {
          url = "https://github.com/googlefonts/roboto/releases/download/v2.138/roboto-unhinted.zip";
          hash = "sha256-ue3PUZinBpcYgSho1Zrw1KHl7gc/GlN1GhWFk6g5QXE=";
          stripRoot = false;
        };

        tlsassistant = pkgs.stdenvNoCC.mkDerivation {
          pname = "tlsassistant";
          version = "3.2";
          src = ./.;

          nativeBuildInputs = [ pkgs.makeWrapper ];

          installPhase = ''
            runHook preInstall

            mkdir -p $out/lib/tlsassistant
            cp -r . $out/lib/tlsassistant/

            # TODO: this can be kept if for some reason someone has built the deps before using nix
            rm -rf $out/lib/tlsassistant/dependencies
            mkdir -p $out/lib/tlsassistant/dependencies

            cp -r ${testssl} $out/lib/tlsassistant/dependencies/testssl.sh
            cp -r ${tls-table} $out/lib/tlsassistant/dependencies/tls-table
            cp -r ${dhe-groups} $out/lib/tlsassistant/dependencies/dhe_groups
            cp -r ${tls-compliance-dataset} $out/lib/tlsassistant/dependencies/tls-compliance-dataset
            cp ${requirementsDb}/requirements.db $out/lib/tlsassistant/dependencies/

            chmod -R u+w $out/lib/tlsassistant/dependencies

            cp ${requirementsDb}/default_versions.json $out/lib/tlsassistant/dependencies/tls-compliance-dataset/utils/

            mkdir -p $out/lib/tlsassistant/dependencies/roboto-unhinted
            cp -r ${roboto-fonts}/* $out/lib/tlsassistant/dependencies/roboto-unhinted/

            makeWrapper ${pythonEnv}/bin/python $out/bin/tlsassistant \
              --set TLSA_DATA_DIR "$out/lib/tlsassistant" \
              --set TLSA_NIX "1" \
              --prefix PATH : "${pkgs.lib.makeBinPath [
                pkgs.bash
                pkgs.coreutils
                pkgs.dnsutils
                pkgs.gawk
                pkgs.gnugrep
                pkgs.gnused
                pkgs.openssl
                pkgs.procps
                pkgs.util-linux
              ]}" \
              --add-flags "$out/lib/tlsassistant/run.py"

            runHook postInstall
          '';
        };
      in {
        packages.default = tlsassistant;
        apps.default = flake-utils.lib.mkApp { drv = tlsassistant; };

        devShells.default = pkgs.mkShell {
          packages = [ pythonEnv pkgs.prisma_6 pkgs.prisma-engines_6 ];
          shellHook = ''
              export TLSA_DATA_DIR="$(pwd)"
              export PRISMA_SCHEMA_ENGINE_BINARY="${pkgs.prisma-engines_6}/bin/schema-engine"
              export PRISMA_QUERY_ENGINE_BINARY="${pkgs.prisma-engines_6}/bin/query-engine"
              export PRISMA_QUERY_ENGINE_LIBRARY="${pkgs.prisma-engines_6}/lib/libquery_engine.node"
              export PRISMA_FMT_BINARY="${pkgs.prisma-engines_6}/bin/prisma-fmt"
            '';
        };
      });
}
