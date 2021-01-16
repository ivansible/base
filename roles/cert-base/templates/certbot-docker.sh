#!/bin/bash
#set -x
set -e

dkr=docker
ctr=certbot-docker
img=certbot/dns-cloudflare:latest

once=
watchtower=1

etcd="{{ certbot_dir }}"
libd="{{ certbot_lib_dir }}"
logd="{{ certbot_log_dir }}"
postd="{{ certbot_post_dir }}"
flag="{{ certbot_flag_file }}"

mounts="-v $etcd:$etcd -v $libd:$libd -v $logd:$logd"
log="$logd/letsencrypt.log"

# verify prerequisites
[[ $(id -u) = 0 ]] || \
    exec sudo -n "$0" "$@"

if ! command -v $dkr >/dev/null; then
    echo "$dkr not found"
    exit 1
fi

tty -s && tty="-it" || tty=

[[ $watchtower ]] \
    && labels="--label=com.centurylinklabs.watchtower.enable=true" \
    || labels=

# prevent "error loading .dockercfg"
if ! [[ $HOME ]]; then
    export HOME=/root
fi

# pull image quietly
[[ $($dkr images -q $img) ]] || \
    $dkr pull --quiet $img

# run command once
case "$1" in
  '')
    echo "usage: $(basename "$0") help | stop | [--once] options..."
    exit 1
    ;;
  -1|--once)
    once=1
    shift
    ;;
  stop)
    exec $dkr stop $ctr
    ;;
esac

if [[ $once ]]; then
    # shellcheck disable=SC2086
    exec $dkr run --rm $tty $mounts $img "$@"
fi

# spawn background container
# shellcheck disable=SC2086
[[ $(docker ps -q -f name=$ctr 2>/dev/null) ]] || \
    $dkr run --detach --rm --init \
        --name $ctr --hostname $ctr $mounts $labels \
        --entrypoint /bin/sleep $img infinity

# exec other commands immediately
[[ $1 = renew ]] || \
    exec $dkr exec $tty $ctr certbot "$@"

# renew certificates
$dkr exec $tty $ctr certbot "$@"
ret=$?

# run renew hooks
if [[ -f $flag ]]; then
    echo "Change flagged: $(cat "$flag")"
    failed=
    if [[ -d $postd ]]; then
        for hook in $postd/*; do
            echo "Running post-hook: $hook" |tee -a "$log"
            [[ -x $hook ]] || continue
            "$hook" || failed="$failed $(basename "$hook")"
        done
    fi
    [ -z "$failed" ] || \
        echo "Failed hooks:$failed" |tee -a "$log"
    rm -f "$flag"
fi

# done
exit $ret
