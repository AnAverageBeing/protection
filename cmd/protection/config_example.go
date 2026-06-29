package main

// configTemplate is the starter configuration. Tokens of the form __FOO__ are
// substituted by `protection config init` (and by the interactive installer)
// via renderConfig. With no flags they fall back to safe defaults.
const configTemplate = `# protection — configuration
# Docs: https://github.com/AnAverageBeing/protection

general:
  name: "__NAME__"          # shown in every alert (hostname / IP / "Protection")
  mode: __MODE__            # server | docker | both
  scan_interval: 5s         # how often detectors run (CPU/disk sampling cadence)
  cooldown: 5m              # suppress duplicate alerts/actions for the same threat
  log_level: info           # debug | info | warn | error
  log_file: /var/log/protection.log
  dry_run: __DRY_RUN__      # true = detect & alert only; flip to false to enforce

detectors:
  miner:
    enabled: true
    cpu_threshold: 85        # percent of one core
    sustained_seconds: 45    # how long CPU must stay high before flagging
    # known_processes: [xmrig, t-rex, ...]   # extends the built-in list
    # pool_ports: [3333, 4444, ...]
  portscan:
    enabled: true
    distinct_ports: 100
    distinct_hosts: 50
    window: 15s
  ddos:
    enabled: true
    pps_threshold: 60000     # outbound packets/sec per container
    bps_threshold: 125000000 # outbound bytes/sec per container (~1 Gbit/s)
    conn_threshold: 1500     # simultaneous outbound connections per process
  zipbomb:
    enabled: true
    scan_paths:
      - /var/lib/pterodactyl/volumes
    ratio_threshold: 150          # uncompressed:compressed
    max_uncompressed: 53687091200 # 50 GiB absolute ceiling
    # Event-driven scanning: when a process spikes CPU + disk writes (an active
    # extraction) we inspect the archive it's reading immediately, instead of
    # waiting for the periodic sweep.
    hot_trigger: true
    hot_cpu_percent: 80
    hot_write_mbps: 25
    full_scan_interval: 30m       # slow backstop sweep of scan_paths
  exploit:
    enabled: true
    flag_reverse_shell: true
    flag_privilege_escalation: true
    watch_paths: [/tmp, /dev/shm, /var/tmp]

alerts:
  discord:
    enabled: __DISCORD_ENABLED__
    webhook_url: "__DISCORD_WEBHOOK__"
    username: Protection
    min_severity: medium
  smtp:
    enabled: false
    host: smtp.example.com
    port: 587
    username: alerts@example.com
    password: ""
    from: alerts@example.com
    to: [admin@example.com]
    tls: true
    min_severity: high
  webhook:
    enabled: false
    url: ""
    method: POST
    headers:
      Authorization: "Bearer changeme"
    min_severity: medium

actions:
  docker:
    enabled: true
    socket: /var/run/docker.sock
  pterodactyl:
    enabled: __PTERO_ENABLED__
    url: "__PTERO_URL__"      # e.g. https://panel.example.com
    api_key: "__PTERO_KEY__"  # Application API key (server read + suspend)
  file:
    enabled: true
    quarantine_dir: /var/lib/protection/quarantine

# Rules map detected threats to enforcement. Evaluated top-to-bottom; every
# matching rule contributes its actions. Available actions:
#   alert, neutralize, kill_container, stop_container, suspend_server,
#   quarantine_file, delete_file, kill_process, log_only
#
# 'neutralize' is smart: it kills the container for containerised threats, or
# the process for bare-VPS host threats — so one rule works everywhere.
rules:
  - name: miners
    categories: [miner]
    min_severity: high
    actions: [neutralize, suspend_server, alert]
  - name: ddos
    categories: [ddos]
    min_severity: high
    actions: [neutralize, suspend_server, alert]
  - name: exploits
    categories: [exploit]
    min_severity: high
    actions: [neutralize, alert]
  - name: zipbombs
    categories: [zipbomb]
    min_severity: medium
    actions: [quarantine_file, alert]
  - name: portscans
    categories: [portscan]
    min_severity: medium
    actions: [alert]
  - name: catch-all
    categories: ["*"]
    min_severity: low
    actions: [alert]
`
