{ name, fuzzerPkgs, addr }:

{ config, pkgs, ... }:
{
  imports = [ ./vultr.nix ];

  deployment.targetHost = addr;
  deployment.targetUser = "mimir";

  networking.hostName = "nixos-fuzz-${name}"; # Define your hostname.
  networking.firewall.allowedTCPPorts = [ 22 80 ];

  boot.kernelPackages = pkgs.linuxPackages_latest;

  ## INSECURE, for fuzzing perf ONLY
  boot.kernelParams = [
    "ibpb=off"
    "ibrs=off"
    "kpti=off"
    "l1tf=off"
    "mds=off"
    "mitigations=off"
    "no_stf_barrier"
    "noibpb"
    "noibrs"
    "nopcid"
    "nopti"
    "nospec_store_bypass_disable"
    "nospectre_v1"
    "nospectre_v2"
    "pcid=off"
    "pti=off"
    "spec_store_bypass_disable=off"
    "spectre_v2=off"
    "stf_barrier=off"
  ];

  systemd.coredump.enable = false;
  security.pam.loginLimits = [
    { domain = "*"; item = "core"; type = "soft"; value = "0"; }
  ];

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
