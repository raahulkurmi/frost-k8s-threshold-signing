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
# use_system SYS OUT_CHECK_JSON: SYS in B0 | B1 | T-5region-<strategy> | T-sameregion-<strategy>
use_system() {
  local sys="$1" out="$2" stamp="$1-$(date -u +%Y%m%dT%H%M%SZ)" pin="" lbset="" mode=external
  coord_down
  case "$sys" in
    B0|B0-anchor) mode=in-tree; coord_egress ;;
    B1)
      coord_compose coordinator-node.b1.yml B1_TLS=secrets-t5 -- up -d >/dev/null
      coord_egress; wait_backend_ready "" || die "B1 replicas not ready"
      pin="$(con coord bash -c "openssl pkey -in ~/tk8s/secrets-b1/key.pem -pubout -outform DER | openssl dgst -sha256 -binary | head -c 16 | base64 | tr '+/' '-_' | tr -d '='")"
      lbset=t5 ;;
    T-5region-*|T-sameregion-*)
      local st="${sys##*-}" sec=secrets-t5; lbset=t5
      [[ "$sys" == T-sameregion-* ]] && { sec=secrets-tsame; lbset=tsame; }
      coord_compose coordinator-node.t.yml COORD_SECRETS=$sec VERIFY_STRATEGY=$st FANOUT=all -- up -d --force-recreate >/dev/null
      # shellcheck disable=SC2046
      coord_egress $(t_endpoints $sec)
      wait_backend_ready "$st" || die "coordinators not ready with strategy=$st"
      pin="$(con coord bash -c "jq -r .kid ~/tk8s/$sec/keys/public-meta.json")" ;;
    *) die "unknown system $sys" ;;
  esac
  con cp sudo /usr/local/bin/frost-7c-switch "$mode" "$stamp" $lbset >/dev/null || die "switch to $sys failed"
  local j
  j="$(con cp sudo /usr/local/bin/frost-7c-check "$mode" $pin)" || { echo "$j" > "$out"; die "check failed for $sys: $j"; }
  jq -c --arg sys "$sys" --arg stamp "$stamp" '. + {system: $sys, stamp: $stamp}' <<<"$j" > "$out"
  log "system $sys ready: $(cat "$out")"
}

# ---- host metrics ----
cpu_sample() { con "$1" awk '/^cpu /{t=0; for(i=2;i<=NF;i++) t+=$i; print t, $5+$6, $9}' /proc/stat; }
cpu_json() { # BEFORE AFTER LOADAVG -> {"busy":..,"steal":..,"load1":..}
  awk -v a="$1" -v b="$2" -v la="$3" 'BEGIN{split(a,x," "); split(b,y," "); split(la,l," "); dt=y[1]-x[1]; if (dt<=0) dt=1;
    printf "{\"cpu_busy_pct\": %.1f, \"cpu_steal_pct\": %.2f, \"load1\": %s}", 100*(1-(y[2]-x[2])/dt), 100*(y[3]-x[3])/dt, l[1]}'
}
