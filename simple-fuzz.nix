  { config, pkgs, ... }:
  { 
    deployment.targetHost = "45.32.226.241";
    deployment.deployer = "mimir";
    services.httpd.enable = true;
    services.httpd.documentRoot = ./dummy;
    networking.firewall.allowedTCPPorts = [ 80 ];
  }
