{ config, lib, pkgs, modulesPath, ... }:
{
  imports =
    [ (modulesPath + "/profiles/qemu-guest.nix")
    ];

  boot.initrd.availableKernelModules = [ "ahci" "xhci_pci" "virtio_pci" "sr_mod" "virtio_blk" ];
  boot.initrd.kernelModules = [ ];
  boot.kernelModules = [ ];
  boot.extraModulePackages = [ ];

  swapDevices = [ ];

  fileSystems."/" = {
    device = "/dev/disk/by-label/nixos";
    fsType = "btrfs";
  };

  boot.loader.grub.enable = true;
  boot.loader.grub.version = 2;
  boot.loader.grub.device = "/dev/vda";

  # Set your time zone.
  time.timeZone = "America/Los_Angeles";

  networking.useDHCP = false;
  networking.interfaces.enp1s0.useDHCP = true;

  # allow SSH here for debug
  networking.firewall.allowedTCPPorts = [ 22 ];

  environment.systemPackages = with pkgs; [
    wget
    neovim
    curl
    tmux
  ];

  # Enable the OpenSSH daemon.
  services.openssh.enable = true;

  users.users.mimir = {
    isNormalUser = true;
    extraGroups = [ "wheel" ]; # Enable ‘sudo’.
    openssh.authorizedKeys.keys = [ "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCuD9sVooBfnm0M4hn7Ts1dNJ3RktGnGK1myHCCKuyTqsIk5t7mCUEWzgPUC1Y+g+TUz7/zU8hnaXyRS1KjqUgA= YubiKey #16944251 PIV Slot 9a" ];
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
}
