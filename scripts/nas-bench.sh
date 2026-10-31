#!/bin/sh
# nas-bench.sh WORK: synthetic benchmark (for a NAS or any Linux host).
# It writes only under WORK, which must not exist. Put the binary to test as
# ./rw-new next to this script, and optionally an older one as ./rw-old to
# compare (case A). Prints time and peak RSS (VmHWM) for each run.
set -u
H=$(cd "$(dirname "$0")" && pwd); W=${1:?WORK}
[ -e "$W" ] && { echo "WORK exists; refusing"; exit 1; }
measure() { label=$1; shift; s=$(date +%s.%N); "$@" & p=$!; peak=0
  while kill -0 $p 2>/dev/null; do kb=$(awk '/VmHWM/ {print $2}' /proc/$p/status 2>/dev/null); [ -n "$kb" ] && [ "$kb" -gt "$peak" ] && peak=$kb; sleep 0.1; done
  wait $p; rc=$?; e=$(date +%s.%N); echo "$label exit=$rc time=$(awk -v a=$s -v b=$e 'BEGIN{printf "%.2f", b-a}')s peak_rss_kb=$peak"; }
echo "== $(uname -m) $(grep MemTotal /proc/meminfo)"; echo "== volume: $(grep ' /volume1 ' /proc/mounts | awk '{print $3}')"
mk_dups() { d=$1; n=$2; mkdir -p "$d/lib" "$d/copies"; head -c 65536 /dev/urandom > "$d/lib/m.mp4"; i=1; while [ $i -le $n ]; do cp "$d/lib/m.mp4" "$d/copies/c$i.mp4"; i=$((i+1)); done; }
echo "== A: 300 identical copies (old vs new)"; mk_dups "$W/a" 300
[ -x "$H/rw-old" ] && measure "old scan" "$H/rw-old" scan "$W/a" --protect-root "$W/a/lib" --no-cache -q -o "$H/a-old.json"
measure "new scan" "$H/rw-new" scan "$W/a" --protect-root "$W/a/lib" --no-cache -q -o "$H/a-new.json"
[ -x "$H/rw-old" ] && echo "old scan.json $(stat -c %s "$H/a-old.json") bytes, new $(stat -c %s "$H/a-new.json") bytes"
[ -x "$H/rw-old" ] && measure "old plan" "$H/rw-old" plan "$H/a-old.json" -o "$H/a-old-plan.json"
measure "new plan" "$H/rw-new" plan "$H/a-new.json" -o "$H/a-new-plan.json"
echo "== B: 3000 identical copies (new only; old would need ~12 GB)"; mk_dups "$W/b" 3000
measure "new scan" "$H/rw-new" scan "$W/b" --protect-root "$W/b/lib" --no-cache -q -o "$H/b.json"
measure "new plan" "$H/rw-new" plan "$H/b.json" -o "$H/b-plan.json"
echo "candidates: $(grep -c '"candidate_remove"' "$H/b-plan.json")"
echo "== C: 10000 unique 4 KiB files + 2000 hard links + 2000 symlinks"; mkdir -p "$W/c/v" "$W/c/h" "$W/c/s"
i=1; while [ $i -le 10000 ]; do head -c 4096 /dev/urandom > "$W/c/v/$i.mp4"; i=$((i+1)); done
i=1; while [ $i -le 2000 ]; do ln "$W/c/v/$i.mp4" "$W/c/h/$i.mp4"; ln -s "../v/$((i+2000)).mp4" "$W/c/s/$i.mp4"; i=$((i+1)); done
measure "new scan io1 nocache" "$H/rw-new" scan "$W/c" --no-cache --io-workers 1 -q -o "$H/c.json"
measure "new scan io4 nocache" "$H/rw-new" scan "$W/c" --no-cache --io-workers 4 -q -o "$H/c.json"
echo "== D: cache effect (3000 copies, same-size files are hashed)"
measure "cold cache" "$H/rw-new" scan "$W/b" --protect-root "$W/b/lib" --cache-dir "$H/cache" -q -o "$H/d1.json"
measure "warm cache" "$H/rw-new" scan "$W/b" --protect-root "$W/b/lib" --cache-dir "$H/cache" -q -o "$H/d2.json"
grep -E '"(partial_hashes|full_hashes|cache_hits)"' "$H/d2.json" | tr -d ' ,'
echo "== E: SIGINT during a scan"
"$H/rw-new" scan "$W/c" "$W/b" --no-cache --io-workers 1 -q -o "$H/e.json" & p=$!; sleep 1; kill -INT $p; wait $p; echo "exit=$? status=$(grep -m1 '"status"' "$H/e.json" | tr -d ' ,')"
echo "== F: unchanged files"; find "$W" -type f | head -2000 | xargs sha256sum > "$H/f1.sha"; "$H/rw-new" scan "$W" --protect-root "$W/a/lib" --no-cache -q -o "$H/f.json"; find "$W" -type f | head -2000 | xargs sha256sum > "$H/f2.sha"; cmp -s "$H/f1.sha" "$H/f2.sha" && echo "OK: no file changed" || echo CHANGED
