# dumper

`tcpdump` monitor that rotates pcap's upon low disk space.

# Installation

## Dependencies

 * python3
 * python-systemd [lib]
 * python-psutil [lib] - (optional, but strongly recommended)

<br>

## Manual installation

    # mkdir -p /etc/dumper
    # cp config.json /etc/dumper/
    # chmod 440 /etc/dumper/*

    # cp dumper.py /usr/bin/dumper
    # chmod 440 /usr/bin/dumper
    # chmod +x /usr/bin/dumper

    # cp systemd/* /etc/systemd/system/

# Running dumper

    # systemctl enable dumper@eno1.service
    # systemctl start dumper@eno1.service

# Configuration

Most tcpdump related configuration *(filters, parameters etc)* is done in `config.json`.<br>
But dumper also takes parameters from the command-line/service scripts. For instance, a per-interface service script can be found under `systemd/` which uses the default config + sends in a interface to dump on.

Any settings done in `config.json` after startup **will override any command line arguments**.<br>
But command-line arguments will override `config.json` the launch.

# Parameters

    --interface=<name> - Which NIC to get network traffic from
    --output=<filename> - Outputs all traffic capture to this filename
    --config=<filename> - Load a config file and monitor for changes, reloads automatically.
    --monitor_config=True - Monitor for configuration changes or not (Default True/Yes)
    --partition=/ - Monitor for free space, pauses capture when we go below --reserved
    --reserved=10 - Will pause capture when below 10% (default)
    --flushlimit=5 - Will flush old pcap's when disk space is below 5% (default)
    --profile=<profile name> - Which profile to run in the config
                              (This option overrides "profile" in the config)
    --instances=1 - How many threads should we run? (Default is 1)

# Features

 * Reloads `config.json` in runtime upon changes to it. (Useful for swapping capturing profile)
 * Multiple `tcpdump` instances can be managed
 * Monitors disk usage, pauses all packet captures at `--reserved` space left.
 * Rotates `.pcap`'s when disk space falls below `--flushlimit`
 