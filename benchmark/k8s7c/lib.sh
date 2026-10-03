# benchmark/k8s7c/lib.sh: operator-side helpers for Phase 7C (sourced by
# deploy/aws/7c/bootstrap.sh and benchmark/k8s7c/run.sh). Portable to macOS bash 3.2.
# Needs: $REPO (repo root), deploy/aws/state/7c/hosts.env.
# shellcheck disable=SC1090,SC1091
S7="$REPO/deploy/aws/state/7c"
source "$S7/hosts.env"
source "$REPO/deploy/multihost/transport.sh"
die() { echo "FATAL: $*" >&2; exit 1; }
log() { echo "[$(date -u +%H:%M:%SZ)] $*"; }
ALL_HOSTS="$(for p in $HOST_ADDRS; do echo "${p%%=*}"; done | tr '\n' ' ')"
COORD_PRIV="$(vm_bind_ip coord)"; CP_PRIV="$(vm_bind_ip cp)"

# ---- network-robust execution (NOTES N60): every ssh/scp failure is recorded
# in "$ERRF.events"; a configuration/rep is valid only if that file is empty.
ERRF=""
_fail() { [[ -n "$ERRF" ]] && echo "$(date -u +%H:%M:%SZ) $1 rc=$2: $(tail -1 "$ERRF" 2>/dev/null | tr -d '\r"')" >> "$ERRF.events"; }
con()   { local rc=0; on "$@" 2>>"${ERRF:-/dev/stderr}" || rc=$?; [[ $rc -eq 0 ]] || _fail "on $1 ${2:-}" "$rc"; return $rc; }
cpipe() { local rc=0; on_pipe "$@" 2>>"${ERRF:-/dev/stderr}" || rc=$?; [[ $rc -eq 0 ]] || _fail "on_pipe $1 ${2:-}" "$rc"; return $rc; }
cpull() { local rc=0; pull "$@" 2>>"${ERRF:-/dev/stderr}" || rc=$?; [[ $rc -eq 0 ]] || _fail "pull $1:$2" "$rc"; return $rc; }
cfg_begin() { ERRF="$(mktemp "${TMPDIR:-/tmp}/c7err.XXXXXX")"; : > "$ERRF.events"; }
cfg_failed() { [[ -s "$ERRF.events" ]]; }
cfg_end() { rm -f "$ERRF" "$ERRF.events"; ERRF=""; }
# rdetach HOST NAME CMD: run CMD detached on HOST (setsid nohup), exit code to /tmp/NAME.rc
rdetach() { con "$1" bash -c "rm -f /tmp/$2.rc; setsid nohup bash -c '$3; echo \$? > /tmp/$2.rc' > /tmp/$2.log 2>&1 < /dev/null &"; }
# rwait HOST NAME MAXSEC: poll for the exit code (poll failures are recorded, polling continues)
rwait() {
  local t0 rc; t0=$(date +%s)
  while :; do
    rc="$(con "$1" bash -c "cat /tmp/$2.rc 2>/dev/null; true")" && [[ -n "$rc" ]] && { echo "$rc"; return 0; }
    (( $(date +%s) - t0 > $3 )) && { echo timeout; return 1; }
    sleep 3
  done
}
wait_net() { # until every host answers (max 30 min)
  local t0 h ok; t0=$(date +%s)
  while :; do
    ok=1; for h in $ALL_HOSTS; do on "$h" true >/dev/null 2>&1 || { ok=0; break; }; done
    [[ $ok == 1 ]] && { log "connectivity OK after $(( $(date +%s) - t0 )) s"; return 0; }
    (( $(date +%s) - t0 > 1800 )) && die "hosts unreachable for 30 min"
    sleep 10
  done
}
# mark_invalid EVENTS_FILE KIND NAME ATTEMPT DEST_DIR FILES...
mark_invalid() {
  local ev="$1" kind="$2" name="$3" att="$4" dest="$5"; shift 5
  local d="$dest/invalid/$name.attempt$att"; mkdir -p "$d"
  local f; for f in "$@"; do [[ -e "$f" ]] && mv "$f" "$d/"; done
  cp "$ERRF.events" "$d/events.txt" 2>/dev/null || true
  jq -cn --arg t "$(date -u +%FT%TZ)" --arg k "$kind" --arg n "$name" --argjson a "$att" --arg e "$(tr '\n' ';' < "$ERRF.events" 2>/dev/null)" \
    '{time_utc: $t, kind: $k, name: $n, attempt: $a, error: $e}' >> "$ev"
  log "INVALID ($kind $name, attempt $att): $(tr '\n' ';' < "$ERRF.events" 2>/dev/null)"
}

# ---- systems (NOTES N67) ----
# Coordinator-node backends: none (B0), B1 (single key), T (secrets-t5 | secrets-tsame).
coord_compose() { # FILE ENV... -- ARGS...: docker compose on the coordinator node
  local file="$1"; shift
  local envs=""; while [[ "$1" != "--" ]]; do envs="$envs $1"; shift; done; shift
  con coord bash -lc "cd ~/tk8s/deploy/aws/7c && env FROST_UID=\$(id -u) COORD_PRIV_IP=$COORD_PRIV$envs docker compose -p c7 -f $file $*"
}
coord_down() {
  con coord bash -lc "cd ~/tk8s/deploy/aws/7c && for f in coordinator-node.t.yml coordinator-node.b1.yml; do env FROST_UID=\$(id -u) COORD_PRIV_IP=$COORD_PRIV COORD_SECRETS=secrets-t5 B1_TLS=secrets-t5 docker compose -p c7 -f \$f down --remove-orphans >/dev/null 2>&1; done; true"
}
coord_egress() { # ENDPOINT... (IP:PORT); none = drop everything from coord-net
  cpipe coord sudo bash -s -- 172.30.3.0/24 "$@" < "$REPO/deploy/multihost/coordinator-egress.sh" >/dev/null
}
t_endpoints() { # SECRETS -> "ip:port ..." from its multihost.env
  con coord bash -c "grep '^SIGNER_ENDPOINTS=' ~/tk8s/$1/multihost.env | cut -d= -f2- | tr ',' '\n' | sed -E 's#^[0-9]+=https://##'" | tr '\n' ' '
}
wait_backend_ready() { # WANT_STRATEGY (empty for B1): all 3 replicas logged ready
  local want="$1" ok r
  for _ in $(seq 1 90); do
    ok=0
    for r in 1 2 3; do
      if [[ -n "$want" ]]; then
        con coord bash -c "docker logs c7-grpc-proxy-$r-1 2>&1 | grep '\"coordinator ready\"' | tail -1 | jq -e 'select(.strategy==\"$want\")' >/dev/null" && ok=$((ok + 1))
      else
        con coord bash -c "docker logs c7-grpc-proxy-$r-1 2>&1 | grep -q 'b1signer ready'" && ok=$((ok + 1))
      fi
    done
    [[ $ok == 3 ]] && return 0
    sleep 2
  done
  return 1
}
# ---- N76/N77 evaluation variants: a T system may carry @<variant> ----
#   (none) the defaults: abort off, n48 admission (N82)    n48  abort off, n48    b  abort on, n48
#   abs    abort on, priority, stable identity (the proposal, N77)
#   ab     abort on, priority, request-ID priority (comparison, N76)
#   slots<k>  abort off, n48, SIGNER_MAX_CONCURRENT=k
#   ab/abs use controller v1 (as measured in N78); v2 / v2nb: stable priority with
#   controller v2, abort on / off (N79, docs/PRIORITY_ADMISSION_V2.md)
variant_cfg() { # VARIANT -> "QUORUM_ABORT ADMISSION MAXCONC PRIORITY CONTROLLER"
  case "$1" in
    "") echo "off n48 - - -" ;; n48) echo "off n48 - - -" ;; b) echo "on n48 - - -" ;;
    ab) echo "on priority - request v1" ;; abs) echo "on priority - stable v1" ;;
    v2) echo "on priority - stable v2" ;; v2nb) echo "off priority - stable v2" ;;
    slots[1-9]*) echo "off n48 ${1#slots} - -" ;;
    *) die "unknown variant @$1" ;;
  esac
}
# signer_config SYS ADMISSION MAXCONC: every signer of SYS gets the admission mode
# and SIGNER_MAX_CONCURRENT (MAXCONC, or 1 while stress caps are on, else the
# default) and QUEUE_SAMPLE; restarted only if changed; verified from its ready line.
signer_config() {
  local sys="$1" adm="$2" mc="$3" pm="${4:--}" pc="${5:--}" pair id h tmp pids="" p rc=0 want_mc want_pm want_pc
  [[ "$mc" == - && -n "${STRESS_ACTIVE:-}" ]] && mc=1
  tmp="$(mktemp -d)"
  for pair in $(t_signer_hosts "$sys"); do
    id="${pair%%:*}" h="${pair#*:}"
    ( cpipe "$h" sudo bash -s -- "$id" "$adm" "$mc" "${QUEUE_SAMPLE:--}" "$pm" "$pc" < "$REPO/deploy/aws/7c/signer-config.sh" > "$tmp/$id" ) &
    pids="$pids $!"
  done
  for p in $pids; do wait "$p" || rc=1; done
  [[ $rc == 0 ]] || { rm -rf "$tmp"; die "signer config for $sys failed"; }
  for pair in $(t_signer_hosts "$sys"); do
    id="${pair%%:*}"
    want_mc="$mc"; [[ "$want_mc" == - ]] && want_mc=2   # t3.micro: NumCPU = 2
    want_pm="$pm"; [[ "$want_pm" == - ]] && { [[ "$adm" == priority ]] && want_pm=stable || want_pm=""; }
    want_pc="$pc"; [[ "$want_pc" == - ]] && { [[ "$adm" == priority ]] && want_pc=v2 || want_pc=""; }
    tail -1 "$tmp/$id" | jq -e --arg a "$adm" --argjson m "$want_mc" --arg p "$want_pm" --arg c "$want_pc" 'select(.admission == $a and .max_concurrent == $m and (.priority // "") == $p and (.priority_controller // "") == $c)' >/dev/null \
      || { cat "$tmp/$id"; rm -rf "$tmp"; die "signer $id of $sys is not running admission=$adm max_concurrent=$want_mc priority=$want_pm controller=$want_pc"; }
  done
  jq -sc 'map({signer_id, admission, priority, priority_controller, priority_epoch, priority_rotation, max_concurrent, max_deadline})' < <(for pair in $(t_signer_hosts "$sys"); do tail -1 "$tmp/${pair%%:*}"; done)
  rm -rf "$tmp"
}

# use_system SYS OUT_CHECK_JSON: SYS in B0 | B1 | T-5region-<strategy>[-<fanout>][@<variant>] | T-sameregion-...
use_system() {
  local sys="$1" out="$2" stamp="$1-$(date -u +%Y%m%dT%H%M%SZ)" pin="" lbset="" mode=external
  local variant="" qa=on adm=n48 mc=- pm=- pc=- sigcfg='null'
  if [[ "$sys" == *@* ]]; then variant="${sys##*@}"; sys="${sys%@*}"; fi
  read -r qa adm mc pm pc <<<"$(variant_cfg "$variant")"
  coord_down
  case "$sys" in
    B0|B0-anchor) mode=in-tree; coord_egress ;;
    B1)
      coord_compose coordinator-node.b1.yml B1_TLS=secrets-t5 -- up -d >/dev/null
      coord_egress; wait_backend_ready "" || die "B1 replicas not ready"
      pin="$(con coord bash -c "openssl pkey -in ~/tk8s/secrets-b1/key.pem -pubout -outform DER | openssl dgst -sha256 -binary | head -c 16 | base64 | tr '+/' '-_' | tr -d '='")"
      lbset=t5 ;;
    T-5region-*|T-sameregion-*)
      # T-<placement>-<strategy>[-<fanout>]; fan-out defaults to all
      local rest="${sys#T-5region-}" sec=secrets-t5; lbset=t5
      [[ "$sys" == T-sameregion-* ]] && { rest="${sys#T-sameregion-}"; sec=secrets-tsame; lbset=tsame; }
      local st="${rest%%-*}" fo="${rest#*-}"; [[ "$fo" == "$rest" ]] && fo=all
      sigcfg="$(signer_config "$sys" "$adm" "$mc" "$pm" "$pc")"
      coord_compose coordinator-node.t.yml COORD_SECRETS=$sec VERIFY_STRATEGY=$st FANOUT=$fo QUORUM_ABORT=$qa -- up -d --force-recreate >/dev/null
      # shellcheck disable=SC2046
      coord_egress $(t_endpoints $sec)
      wait_backend_ready "$st" || die "coordinators not ready with strategy=$st"
      local r; for r in 1 2 3; do
        con coord bash -c "docker logs c7-grpc-proxy-$r-1 2>&1 | grep '\"coordinator ready\"' | tail -1 | jq -e 'select(.fanout==\"$fo\" and .coordinator_id==$r and .quorum_abort==$([[ $qa == on ]] && echo true || echo false))' >/dev/null" \
          || die "coordinator $r not running fanout=$fo coordinator_id=$r quorum_abort=$qa"
      done
      pin="$(con coord bash -c "jq -r .kid ~/tk8s/$sec/keys/public-meta.json")" ;;
    *) die "unknown system $sys" ;;
  esac
  # A switch can take several minutes (switch.sh bounds its own waits); the ssh
  # alarm is raised to 25 min for it. It is idempotent, so a failure is retried once.
  local swlog try rc t0 sw_s; swlog="$(mktemp "${TMPDIR:-/tmp}/c7switch.XXXXXX")"
  for try in 1 2; do
    t0=$(date +%s); rc=0
    ON_ALARM=1500 con cp sudo /usr/local/bin/frost-7c-switch "$mode" "$stamp-try$try" $lbset > "$swlog" 2>&1 || rc=$?
    sw_s=$(( $(date +%s) - t0 ))
    [[ $rc == 0 ]] && break
    echo "switch to $sys failed (try $try, rc $rc, ${sw_s} s); output:"; tail -20 "$swlog"
    [[ $try == 2 ]] && { rm -f "$swlog"; die "switch to $sys failed twice"; }
  done
  rm -f "$swlog"; stamp="$stamp-try$try"
  local j
  j="$(con cp sudo /usr/local/bin/frost-7c-check "$mode" $pin)" || { echo "$j" > "$out"; die "check failed for $sys: $j"; }
  [[ -n "$variant" ]] && sys="$sys@$variant"
  jq -c --arg sys "$sys" --arg stamp "$stamp" --argjson sw "$sw_s" --argjson tries "$try" --arg qa "$qa" --argjson sig "$sigcfg" \
    '. + {system: $sys, stamp: $stamp, switch_seconds: $sw, switch_tries: $tries} + (if $sig == null then {} else {quorum_abort: $qa, signers: $sig} end)' <<<"$j" > "$out"
  log "system $sys ready: $(cat "$out")"
}

# ---- host metrics ----
cpu_sample() { con "$1" awk '/^cpu /{t=0; for(i=2;i<=NF;i++) t+=$i; print t, $5+$6, $9}' /proc/stat; }
cpu_json() { # BEFORE AFTER LOADAVG -> {"busy":..,"steal":..,"load1":..}
  awk -v a="$1" -v b="$2" -v la="$3" 'BEGIN{split(a,x," "); split(b,y," "); split(la,l," "); dt=y[1]-x[1]; if (dt<=0) dt=1;
    printf "{\"cpu_busy_pct\": %.1f, \"cpu_steal_pct\": %.2f, \"load1\": %s}", 100*(1-(y[2]-x[2])/dt), 100*(y[3]-x[3])/dt, l[1]}'
}

# ---- signers of a T system (lever check, stress test) ----
t_signer_hosts() { # SYS -> "id:host ..."
  local p=t5; [[ "$1" == T-sameregion-* ]] && p=ts
  echo "1:$p-1 2:$p-2 3:$p-3 4:$p-4 5:$p-5"
}
# signer_cpu_snapshot SYS OUT: per signer "id host wall_ns cpu_usage_ns host_total host_idle", in parallel
signer_cpu_snapshot() {
  local sys="$1" out="$2" pair id h
  : > "$out"
  for pair in $(t_signer_hosts "$sys"); do
    id="${pair%%:*}" h="${pair#*:}"
    ( v="$(con "$h" bash -c "echo \$(date +%s%N) \$(systemctl show frost-signer-$id -p CPUUsageNSec --value) \$(awk '/^cpu /{t=0; for(i=2;i<=NF;i++) t+=\$i; print t, \$5+\$6}' /proc/stat)")" && echo "$id $h $v" >> "$out" ) &
  done
  wait
  [[ "$(wc -l < "$out" | tr -d ' ')" == 5 ]]
}
# signer_cpu_json BEFORE AFTER -> {"signers":[{signer_id, host, process_cpu_pct (of one vCPU), host_busy_pct}], mean, max}
signer_cpu_json() {
  local b="$1" a="$2"
  join <(sort "$b") <(sort "$a") | awk '{
      id=$1; wall=$8-$3; cpu=$9-$4; ht=$10-$5; hi=$11-$6; if (wall<=0) wall=1; if (ht<=0) ht=1;
      printf "{\"signer_id\": %d, \"host\": \"%s\", \"process_cpu_pct\": %.1f, \"host_busy_pct\": %.1f}\n", id, $2, 100*cpu/wall, 100*(1-hi/ht)
    }' | jq -s '{signers: ., signer_cpu_mean_pct: ((map(.process_cpu_pct) | add) / length), signer_cpu_max_pct: (map(.process_cpu_pct) | max)}'
}
