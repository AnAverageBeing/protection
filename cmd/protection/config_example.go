package main

// exampleConfig is the starter configuration written by `protection config init`.
// It documents every option with security-first defaults.
const exampleConfig = `# protection — configuration
# Docs: https://github.com/AnAverageBeing/protection

general:
  scan_interval: 10s        # how often detectors run
  cooldown: 5m              # suppress duplicate alerts/actions for the same threat
  log_level: info           # debug | info | warn | error
  log_file: /var/log/protection.log
  dry_run: true             # IMPORTANT: start in dry-run, watch alerts, then disable

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
    ratio_threshold: 150     # uncompressed:compressed
    max_uncompressed: 53687091200  # 50 GiB absolute ceiling
    scan_interval: 5m
  exploit:
    enabled: true
    flag_reverse_shell: true
    flag_privilege_escalation: true
    watch_paths: [/tmp, /dev/shm, /var/tmp]

alerts:
  discord:
    enabled: false
    webhook_url: ""
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
    enabled: false
    url: https://panel.example.com
    api_key: ""             # Application API key with server read + suspend
  file:
    enabled: true
    quarantine_dir: /var/lib/protection/quarantine

# Rules map detected threats to enforcement. Evaluated top-to-bottom; every
# matching rule contributes its actions. Available actions:
#   alert, kill_container, stop_container, suspend_server,
#   quarantine_file, delete_file, kill_process, log_only
rules:
  - name: miners
    categories: [miner]
    min_severity: high
    actions: [kill_container, suspend_server, alert]
  - name: ddos
    categories: [ddos]
    min_severity: high
    actions: [kill_container, suspend_server, alert]
  - name: exploits
    categories: [exploit]
    min_severity: high
    actions: [kill_container, alert]
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
