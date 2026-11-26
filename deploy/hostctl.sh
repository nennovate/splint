#!/bin/bash
# Runs one of the host's own commands the way the service runs the host: as the splint user, with
# the settings in /etc/splint/host.env, read by systemd as it reads them for the service. The
# running host isn't touched, and nothing restarts.
#
#   sudo splint-hostctl check           Says which setting a start would refuse, and why.
#   sudo splint-hostctl codes add 5     Makes five signup codes, which the host takes at once.
#   sudo splint-hostctl codes list      Every signup code, unused first, then those spent.
#   sudo splint-hostctl counts          How many agents, owners and other hosts use this host, as
#                                       numbers under fixed labels. It only reads, and prints no names.
#   sudo splint-hostctl key code        Sets the host's recovery code, once, and prints it.
#   sudo splint-hostctl key rotate      Gives the host a new key, which other hosts follow.
#   sudo splint-hostctl key recover     Replaces a lost or stolen key with the code, read from stdin.
#   sudo splint-hostctl key restore     Puts a backup's key and ID back, which splint-restore runs.
#   sudo splint-hostctl close DAY       Closes the host to new agents and tells its agents to move by
#                                       DAY (YYYY-MM-DD). close alone says what's set, and close
#                                       cancel takes it back.
#
# SPLINT_HOST_BINARY names another build of the host to run, which is how install.sh checks a new
# one against this server's settings before it replaces the one that's running.
set -euo pipefail
if [ "$(id -u)" != 0 ]; then
    echo "splint-hostctl reads the host's settings, which needs root: sudo splint-hostctl $*" >&2
    exit 1
fi
# With nothing after it the host's binary runs a host, and one is running already.
if [ $# = 0 ]; then
    set -- help
fi
exec systemd-run --quiet --wait --collect --pipe \
    --property=User=splint --property=Group=splint \
    --property=EnvironmentFile=/etc/splint/host.env \
    --setenv=NO_COLOR=1 \
    "${SPLINT_HOST_BINARY:-/usr/local/bin/splint-host}" "$@"
