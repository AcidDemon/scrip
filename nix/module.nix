{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.scrip;
  settingsFormat = pkgs.formats.toml { };
  # Absolute db_path: the CLI resolves a relative one from the caller's cwd.
  configFile = settingsFormat.generate "scrip.toml" (cfg.settings // { db_path = dbPath; });

  # App defaults (src/config.rs) as fallbacks for the keys the units need.
  portOf = addr: lib.toInt (lib.last (lib.splitString ":" addr));
  tcpPorts = lib.unique (map portOf (cfg.settings.listen_tcp or [ "[::]:9999" ]));
  httpPorts = lib.unique (map portOf (cfg.settings.listen_http or [ "127.0.0.1:8080" ]));
  # db_path may be relative (the app default is a bare "scrip.db"), and both
  # units resolve it against WorkingDirectory. Normalise it the same way here,
  # or ReadWritePaths below would render "-." and systemd would reject it.
  stateDir = "/var/lib/scrip";
  dbPath =
    let
      p = cfg.settings.db_path or "scrip.db";
    in
    if lib.hasPrefix "/" p then p else "${stateDir}/${p}";
  # nft takes either a bare port or a braced set, so build whichever fits.
  # The ruleset then follows listen_tcp instead of assuming the default and
  # silently protecting a port nothing listens on.
  nftTcpPorts =
    if builtins.length tcpPorts == 1 then
      toString (builtins.head tcpPorts)
    else
      "{ " + lib.concatMapStringsSep ", " toString tcpPorts + " }";
in
{
  options.services.scrip = {
    enable = lib.mkEnableOption "scrip, the terminal pastebin";

    package = lib.mkOption {
      type = lib.types.package;
      description = "The scrip package to run. Defaults to this flake's package.";
    };

    settings = lib.mkOption {
      type = settingsFormat.type;
      default = { };
      example = {
        base_url = "https://paste.example.com";
        listen_http = [ "127.0.0.1:8080" ];
      };
      description = ''
        Contents of scrip.toml, passed to `scrip run --config`. Every key is
        optional; the binary carries its own defaults (full list in the root
        README).
      '';
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Open the intake (listen_tcp) ports in the NixOS firewall.";
    };

    nftables.enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Install the scrip anti-abuse nftables table (ban sets, per-source
        connection caps, flood limiters) and export stored bans into it at
        boot. Enables networking.nftables; this table is scrip-scoped only, a
        default-drop base firewall remains the operator's job.
      '';
    };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [
    {
      users.users.scrip = {
        isSystemUser = true;
        group = "scrip";
        home = "/var/lib/scrip";
      };
      users.groups.scrip = { };

      environment.etc."scrip/scrip.toml".source = configFile;
      environment.systemPackages = [ cfg.package ];

      networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall tcpPorts;

      systemd.services.scrip = {
        description = "scrip pastebin";
        after = [ "network-online.target" ] ++ lib.optional cfg.nftables.enable "scrip-firewall.service";
        wants = [ "network-online.target" ] ++ lib.optional cfg.nftables.enable "scrip-firewall.service";
        wantedBy = [ "multi-user.target" ];
        # Never latch permanently failed (e.g. repeated OOM kills); Restart+RestartSec pace retries.
        unitConfig.StartLimitIntervalSec = 0;
        serviceConfig = {
          ExecStart = "${lib.getExe cfg.package} run --config ${configFile}";
          User = "scrip";
          Group = "scrip";
          # The app-default db_path is relative; resolve it in the state dir.
          WorkingDirectory = stateDir;
          Restart = "on-failure";
          RestartSec = 5;
          # 10s connection drain + 1s per spawned task, and task count is
          # listen_tcp.len() + listen_http.len() + 3, so the shipped defaults
          # (2 + 1 + 3) already need 16s.
          TimeoutStopSec = 45;
          NoNewPrivileges = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          PrivateDevices = true;
          ProtectKernelTunables = true;
          ProtectControlGroups = true;
          RestrictAddressFamilies = "AF_INET AF_INET6 AF_UNIX";
          StateDirectory = "scrip";
          # Paste bodies and any ban table are readable only by the service user.
          StateDirectoryMode = "0700";
          # Needs systemd 256+; on older systemd use PrivateUsers = "yes".
          PrivateUsers = "self";
          RemoveIPC = true;
          # max_conns (1024) x max_paste_bytes (512KiB) = 512MiB, but a paste is
          # held as the request body, a copy, and under encrypt_at_rest a sealed
          # copy, so worst case is ~1.5GiB of intake buffers + SQLite cache +
          # runtime.
          MemoryMax = "2G";
          LimitNOFILE = 8192;
          # The deny-list is additive: it narrows the allow-list, since
          # @system-service still admits resource-tuning, privileged and
          # obsolete calls scrip never makes. One `~` negates the whole list.
          SystemCallFilter = [
            "@system-service"
            "~@resources @privileged @obsolete"
          ];
          RestrictNamespaces = true;
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          RestrictSUIDSGID = true;
          RestrictRealtime = true;
          CapabilityBoundingSet = "";
          ProtectKernelModules = true;
          ProtectKernelLogs = true;
          ProtectClock = true;
          ProtectHostname = true;
          UMask = "0077";
          # A core dump would write paste plaintext, and any at-rest
          # encryption keys derived from the URLs in flight, to disk in a
          # file no takedown touches.
          LimitCORE = 0;
          ProtectProc = "invisible";
          ProcSubset = "pid";
          SystemCallArchitectures = "native";
          # Must stay above tokio's blocking pool (up to 512 threads) + runtime workers,
          # or a load burst turns into pthread_create failures and a crash loop.
          TasksMax = 640;
          SocketBindDeny = "any";
          SocketBindAllow = map (p: "tcp:${toString p}") (tcpPorts ++ httpPorts);
        };
      };
    }

    (lib.mkIf cfg.nftables.enable {
      # An empty listen_tcp would render `tcp dport {  }`, which fails the
      # whole ruleset at activation rather than here.
      assertions = [
        {
          assertion = tcpPorts != [ ];
          message = "services.scrip.nftables.enable needs at least one listen_tcp address to protect.";
        }
      ];
      networking.nftables.enable = true;
      # Same ruleset as deploy/nftables-scrip.conf, loaded declaratively. The
      # `delete table` preamble that file carries is absent here because
      # networking.nftables.tables already prepends its own.
      networking.nftables.tables.scrip = {
        family = "inet";
        content = ''
          # The timeout flag is what lets a temporary auto-ban expire in the
          # kernel instead of persisting until reboot.
          set scrip_bans4 { type ipv4_addr; flags interval,timeout; }
          set scrip_bans6 { type ipv6_addr; flags interval,timeout; }
          set conns4 { type ipv4_addr; flags dynamic; size 65535; }
          set conns6 { type ipv6_addr; flags dynamic; size 65535; }
          set conns48 { type ipv6_addr; flags dynamic; size 65535; }
          set flood4 { type ipv4_addr; flags dynamic; timeout 2m; size 65535; }
          set flood6 { type ipv6_addr; flags dynamic; timeout 2m; size 65535; }
          set flood48 { type ipv6_addr; flags dynamic; timeout 2m; size 65535; }

          chain input {
              type filter hook input priority 0; policy accept;
              ip saddr @scrip_bans4 tcp dport ${nftTcpPorts} drop
              ip6 saddr @scrip_bans6 tcp dport ${nftTcpPorts} drop
              # Both counters key on the same thing the app and the rate
              # rules do: the address for v4, the /64 for v6. Counting v6 per
              # /128 would let one /64 open unlimited connections by walking
              # its host part.
              tcp dport ${nftTcpPorts} ct state new add @conns4 { ip saddr ct count over 10 } drop
              tcp dport ${nftTcpPorts} ct state new add @conns6 { ip6 saddr and ffff:ffff:ffff:ffff:: ct count over 10 } drop
              # Per-source connect rate; v6 keyed on the /64 to match the app's source keying.
              tcp dport ${nftTcpPorts} ct state new add @flood4 { ip saddr limit rate over 30/minute } drop
              tcp dport ${nftTcpPorts} ct state new add @flood6 { ip6 saddr and ffff:ffff:ffff:ffff:: limit rate over 30/minute } drop
              # One routed /48 is 65,536 /64 identities, so a per-/64 cap alone
              # is rotated around. 8x the /64 values, matching the app's own
              # /48 tier.
              tcp dport ${nftTcpPorts} ct state new add @conns48 { ip6 saddr and ffff:ffff:ffff:: ct count over 80 } drop
              tcp dport ${nftTcpPorts} ct state new add @flood48 { ip6 saddr and ffff:ffff:ffff:: limit rate over 240/minute } drop
              # Backstop only, sized above aggregate legitimate load; per-source rules above do the real limiting.
              tcp dport ${nftTcpPorts} ct state new limit rate over 2000/minute drop
          }
        '';
      };

      systemd.services.scrip-firewall = {
        description = "scrip ban export into nftables";
        # nftables.service loads the base table (a full-ruleset reload would
        # wipe exported elements); run after it, before scrip starts.
        after = [ "nftables.service" ];
        before = [ "scrip.service" ];
        wantedBy = [ "multi-user.target" ];
        # A full-ruleset reload wipes the exported ban elements, and a
        # RemainAfterExit oneshot would never re-add them. Re-run this unit
        # when nftables restarts, and re-export on reload.
        partOf = [ "nftables.service" ];
        # Forward nftables reloads to ExecReload. unitConfig keys are emitted
        # verbatim and must use systemd's capitalization.
        unitConfig.ReloadPropagatedFrom = [ "nftables.service" ];
        serviceConfig = {
          Type = "oneshot";
          RemainAfterExit = true;
          # Runs as root: nft needs CAP_NET_ADMIN. Export to a file first so a
          # failing export fails the unit instead of nft silently loading empty
          # stdin. Before the first run creates the database, the export only
          # flushes the sets.
          ExecStart = pkgs.writeShellScript "scrip-ban-export" ''
            set -e
            ${lib.getExe cfg.package} ban export --config ${configFile} > /run/scrip/bans.nft
            ${pkgs.nftables}/bin/nft -f /run/scrip/bans.nft
          '';
          ExecReload = pkgs.writeShellScript "scrip-ban-reexport" ''
            set -e
            ${lib.getExe cfg.package} ban export --config ${configFile} > /run/scrip/bans.nft
            ${pkgs.nftables}/bin/nft -f /run/scrip/bans.nft
          '';
          NoNewPrivileges = true;
          # All nft needs to talk to the kernel's netfilter tables.
          CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
          ProtectSystem = "strict";
          # ProtectSystem=strict leaves /run read-only; this is the one writable
          # spot, and it is where the ban export lands.
          RuntimeDirectory = "scrip";
          # `scrip ban export` opens the database read-write (WAL needs to
          # create the -shm file), so strict confinement would fail it
          # outright. Leading `-`: the path does not exist until scrip has run
          # once. Not StateDirectory=, which would chown the directory away
          # from the scrip user this unit does not run as.
          ReadWritePaths = [ "-${builtins.dirOf dbPath}" ];
          # Resolve relative db_path values as scrip.service does. A wrong
          # working directory would find no database and silently export no bans.
          WorkingDirectory = stateDir;
          ProtectHome = true;
          PrivateTmp = true;
          PrivateDevices = true;
          ProtectKernelTunables = true;
          ProtectKernelModules = true;
          ProtectKernelLogs = true;
          ProtectControlGroups = true;
          ProtectClock = true;
          ProtectHostname = true;
          ProtectProc = "invisible";
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          # AF_NETLINK is how nft reaches the kernel.
          RestrictAddressFamilies = "AF_NETLINK AF_UNIX AF_INET AF_INET6";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          SystemCallArchitectures = "native";
          SystemCallFilter = "@system-service";
          # The export is the list of banned CIDRs; at root's default 0022 it
          # would be world-readable to every local user.
          UMask = "0077";
          LimitCORE = 0;
        };
      };
    })
  ]);
}
