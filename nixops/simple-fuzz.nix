{ name, fuzzerPkgs }:

{ config, pkgs, ... }:
{
  imports = [ ./vultr.nix ];

  deployment.targetHost = "45.32.226.241";
  deployment.targetUser = "mimir";

  networking.hostName = "nixos-fuzz-${name}"; # Define your hostname.
  networking.firewall.allowedTCPPorts = [ 22 80 ];

  environment.systemPackages = with pkgs; [
    aflplusplus
    valgrind
    gdb
    strace
    python39
  ] ++ fuzzerPkgs;

  systemd.tmpfiles.rules = [
    "d /fuzz 0700 mimir - - -"
  ];
}
