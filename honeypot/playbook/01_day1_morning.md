# 01 — Day 1 Morning (April 23, 08:00–12:00)

**Outcome by 12:00:** Cowrie reachable on port 2222. Ground truth captured. Ollama warm. Router installed. First end-to-end test passing.

---

## 08:00 — Kickoff

- Listen for spec changes
- Note any clarifications about Red Team or scoring
- Get on team Slack
- Pick up hardware (2 Pi 5s)

---

## 09:00 — Sub-teams split

### Sub-team A — Cowrie + filesystem (3 people)

**A1 — Hardware lead**
- Boot both Pis. Note their IPs.
- Verify Cowrie running on honeypot: `ssh cowrie@<honeypot>; ~/cowrie/bin/cowrie status`
- Verify external reachability: from laptop, `ssh root@<honeypot> -p 2222` (password: root)
- **Once verified: post the IP in Slack** (this is the official "we're up" signal)

**A2 — Ground truth lead**
- SSH into clean Pi: `ssh pi@<clean_pi>` (password: raspberry)
- Copy capture script: `scp src/scripts/capture_groundtruth.sh pi@<clean_pi>:~/`
- Run it: `ssh pi@<clean_pi> 'bash ~/capture_groundtruth.sh'`
- This produces `/tmp/groundtruth.tgz` with 70+ command captures
- scp tarball back to your laptop, then to honeypot:
  ```
  scp pi@<clean_pi>:/tmp/groundtruth.tgz .
  scp groundtruth.tgz cowrie@<honeypot>:~/
  ```

**A3 — Filesystem lead**
- On honeypot Pi, inspect current Cowrie virtual FS:
  ```
  cd ~/cowrie && source cowrie-env/bin/activate
  bin/fsctl share/cowrie/fs.pickle
  # In fsctl: ls /, ls /home, cat /etc/os-release, exit
  ```
- Note what Cowrie ships with vs what a real Pi has
- Plan patches for `/etc/os-release`, `/etc/passwd`, `/etc/hostname`, `/proc/cpuinfo`, `/boot/firmware/config.txt`, `/home/pi/.bash_history`

### Sub-team B — Intelligence + cloud (2 people)

**B1 — Ollama lead**
- SSH into honeypot as `cowrie` (password: honeypot)
- Get the kit onto the Pi: from your laptop, `scp -r scalpel cowrie@<honeypot>:~/`
- Run setup: `cd ~/scalpel && bash src/scripts/setup_llm.sh qwen2.5:1.5b`
- Install keepalive cron:
  ```
  (crontab -l 2>/dev/null; echo "*/4 * * * * /home/cowrie/scalpel-kit/src/scripts/keepalive.sh > /dev/null 2>&1") | crontab -
  ```
- Benchmark response time:
  ```
  for cmd in "uname -a" "ps aux" "find / -name foo"; do
    time curl -s http://localhost:11434/api/generate -d "{\"model\":\"qwen2.5:1.5b\",\"prompt\":\"\$ $cmd\n\",\"stream\":false,\"keep_alive\":\"24h\"}" > /dev/null
  done
  ```
- If most responses >1.5s, downgrade to `qwen2.5:0.5b` and re-benchmark

**B2 — AWS Lambda lead**
- On your laptop: `cd scalpel && bash src/scripts/deploy_cloud.sh`
- Note the FUNCTION_URL it prints
- Test from your laptop:
  ```
  curl -X POST <function_url> -d '{"command":"find / -name foo","history":[]}'
  ```
- SSH to honeypot, set the URL:
  ```
  echo "export SVCD_CLOUD_URL=<function_url>" >> ~/.bashrc
  source ~/.bashrc
  ```

---

## 10:30 — Decision Gate #1 (5 min standup)

Each lead reports YES/NO:
- A1: Cowrie reachable from laptop on port 2222?
- A2: Ground truth tarball on honeypot?
- B1: Ollama responding under 1.5s?
- B2: Lambda deployed, callable from Pi?

If 2+ NOs, re-prioritize. Cowrie reachability is a HARD requirement — drop everything to fix.

---

## 11:00 — Wire it all together

1. **Ingest ground truth** (A2 owns)
   ```
   ssh cowrie@<honeypot>
   cd ~/scalpel
   bash src/scripts/ingest_data.sh ~/groundtruth.tgz
   ```

2. **Install router into Cowrie** (B1 owns)
   ```
   bash src/scripts/install_svcd.sh
   ```

3. **Restart Cowrie**
   ```
   ~/cowrie/bin/cowrie restart
   tail -f ~/cowrie/var/log/cowrie/cowrie.log  # watch for errors
   ```

4. **End-to-end test** (everyone watches)
   From a laptop:
   ```
   ssh root@<honeypot> -p 2222
   # password: root
   uname -a       # → should hit Tier 1, fast Pi response
   foobarbaz      # → should hit Tier 2, "command not found"
   find / -name x # → should hit Tier 3 if Lambda up, else Tier 2
   ```

5. **Verify metrics flowing**
   ```
   tail -f /var/log/journal/svcd/events.jsonl
   ```
   Each command above should produce a JSON line with the right tier.

---

## 11:45 — Start dashboard (with SSH tunnel — paranoid mode)

The dashboard binds to localhost ONLY (so the red team can't find it on a port scan). To view from your laptop:

```bash
# On honeypot Pi
cd ~/scalpel-kit
nohup python3 src/dashboard/monitor.py > /tmp/m.log 2>&1 &

# On laptop (in a separate terminal that you keep open):
ssh -N -L 8080:127.0.0.1:8080 cowrie@<honeypot_ip>

# Then open in laptop browser:
#   http://127.0.0.1:8080
```

The `-N` flag means "don't run a remote command, just forward the port." Leave that terminal open for the entire hackathon.

**Verify dashboard NOT publicly exposed:**
```bash
ssh cowrie@<honeypot> 'ss -tlnp | grep 8080'
# Should show 127.0.0.1:8080 ONLY. If you see 0.0.0.0:8080, fix it before continuing.
```

---

## 12:00 — Morning checkpoint

**MUST be true:**
- [ ] Cowrie running, externally reachable on port 2222 (IP posted in Slack)
- [ ] Ground truth ingested (`ls ~/scalpel-kit/ground_truth/cmd_*.txt | wc -l` > 50)
- [ ] Ollama loaded (`curl http://localhost:11434/api/ps` shows model)
- [ ] Router installed in Cowrie (test command flowed through metrics log)
- [ ] Dashboard live, accessible from laptop

**Should be true:**
- [ ] Lambda URL set in `~/.bashrc` and reachable
- [ ] At least 5 different commands tested end-to-end

If any MUST item is false, lunch becomes a working lunch.

---

## Lunch (12:00–13:00) — split shift

Half eats while half watches the Pi. Swap at 12:30.
