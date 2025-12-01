{
  description = "Burp Suite Image Viewer extension";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";

  outputs = { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        f pkgs);
    in
    {
      packages = forAllSystems (pkgs: {
        default = pkgs.stdenv.mkDerivation {
          pname = "burp-image-viewer";
          version = "0.1.0";
          src = ./.;
          nativeBuildInputs = [ pkgs.jdk21 ];

          buildPhase = ''
            bash scripts/build.sh
          '';

          installPhase = ''
            mkdir -p $out/share/java
            cp dist/burp-image-viewer.jar $out/share/java/
          '';
        };
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          buildInputs = [
            pkgs.jdk21
            pkgs.gradle
          ];

          shellHook = ''
            export CLASSPATH=$PWD/lib/burp-extender-api.jar${CLASSPATH:+":$CLASSPATH"}
            echo "CLASSPATH set to include burp-extender-api.jar"
          '';
        };
      });
    };
}
