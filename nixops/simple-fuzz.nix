{ config, pkgs, ... }:
{
  imports = [ ./vultr.nix ];

  deployment.targetHost = "45.32.226.241";
  deployment.targetUser = "mimir";

  networking.hostName = "nixos-fuzz-vultr1"; # Define your hostname.
  networking.firewall.allowedTCPPorts = [ 22 80 ];

  services.nginx = {
    enable = true;
    virtualHosts."example.com" = {
      default = true;
      root = ./dummy;
    };
  };

  environment.systemPackages = with pkgs; [
    aflplusplus
    valgrind
    gdb
    strace
    python39
  ];

  systemd.tmpfiles.rules = [
    "d /fuzz 0700 mimir - - -"
  ];
}
