{ config, pkgs, ... }:
{
  deployment.targetHost = "45.32.226.241";
  deployment.targetUser = "mimir";

  networking.firewall.allowedTCPPorts = [ 22 80 ];

  fileSystems."/" = {
    device = "/dev/disk/by-label/nixos";
    fsType = "btrfs";
  };

  boot.loader.grub.enable = true;
  boot.loader.grub.version = 2;
  boot.loader.grub.device = "/dev/vda";

  networking.hostName = "nixos-fuzz-vultr1"; # Define your hostname.

  # Set your time zone.
  time.timeZone = "America/Los_Angeles";

  # The global useDHCP flag is deprecated, therefore explicitly set to false here.
  # Per-interface useDHCP will be mandatory in the future, so this generated config
  # replicates the default behaviour.
  networking.useDHCP = false;
  networking.interfaces.enp1s0.useDHCP = true;

  environment.systemPackages = with pkgs; [
    wget neovim curl aflplusplus valgrind gdb strace tmux
  ];

  # Enable the OpenSSH daemon.
  services.openssh.enable = true;

  users.users.mimir = {
          isNormalUser = true;
          extraGroups = [ "wheel" ]; # Enable ‘sudo’.
          openssh.authorizedKeys.keys = ["ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCuD9sVooBfnm0M4hn7Ts1dNJ3RktGnGK1myHCCKuyTqsIk5t7mCUEWzgPUC1Y+g+TUz7/zU8hnaXyRS1KjqUgA= YubiKey #16944251 PIV Slot 9a"];
  };
  nix.trustedUsers = [ "mimir" ];

  security.sudo.wheelNeedsPassword = false;

  # This value determines the NixOS release from which the default
  # settings for stateful data, like file locations and database versions
  # on your system were taken. It‘s perfectly fine and recommended to leave
  # this value at the release version of the first install of this system.
  # Before changing this value read the documentation for this option
  # (e.g. man configuration.nix or on https://nixos.org/nixos/options.html).
  system.stateVersion = "20.09"; # Did you read the comment?

    services.nginx = {
      enable = true;
      virtualHosts."example.com" = {
        default = true;
        root = ./dummy;
      };
    };
  
}
