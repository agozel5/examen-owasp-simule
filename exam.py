#!/usr/bin/env python3
"""Outil de l'examen simule (stdlib uniquement).

    python exam.py start            demarre les labs, genere les flags, lance le chrono
    python exam.py status           temps restant, labs, flags valides
    python exam.py submit lab1 FLAG{...}
    python exam.py grade            lance les tests de securite/fonctionnels et note
    python exam.py stop             arrete les labs
    python exam.py reset            arrete tout et efface l'etat (.exam/)
"""
import argparse
import hashlib
import json
import os
import secrets
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
STATE_DIR = ROOT / ".exam"
STATE_FILE = STATE_DIR / "state.json"
DURATION_S = 45 * 60

LABS = {
    "lab1": {"dir": "lab1_idor", "port": 5001, "title": "FactuPro",
             "goal": "Compte fourni : wiener / peter. Un flag est cache dans les donnees d'un autre client."},
    "lab2": {"dir": "lab2_path_traversal", "port": 5002, "title": "ShopImages",
             "goal": "Le flag est dans secret/flag.txt, a cote du dossier images/ servi par l'application."},
    "lab3": {"dir": "lab3_sqli", "port": 5003, "title": "Intranet RH",
             "goal": "Le flag est affiche dans le panneau /admin. Vous n'avez aucun identifiant administrateur."},
    "lab4": {"dir": "lab4_ssrf", "port": 5004, "title": "StockCheck",
             "goal": "Le flag est sur /admin (console interne, 403 en acces direct). Passez par l'application."},
    "lab5": {"dir": "lab5_jwt", "port": 5005, "title": "AdminPanel",
             "goal": "Compte fourni : wiener / peter. Le flag est sur /admin, reserve a 'administrator'."},
}


# ------------------------------------------------------------------ outils
def sha(text):
    return hashlib.sha256(text.strip().encode()).hexdigest()


def load_state():
    if not STATE_FILE.exists():
        return None
    return json.loads(STATE_FILE.read_text())


def save_state(state):
    STATE_DIR.mkdir(exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))


def is_up(port):
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1)
        return True
    except urllib.error.HTTPError:
        return True
    except Exception:
        return False


def fmt(seconds):
    seconds = int(max(0, seconds))
    return f"{seconds // 60:02d}:{seconds % 60:02d}"


def norm_lab(name):
    name = name.lower().strip()
    if name.isdigit():
        name = "lab" + name
    if name not in LABS:
        sys.exit(f"Lab inconnu : {name}. Choix : {', '.join(LABS)}")
    return name


def stop_labs(state):
    for info in (state or {}).get("labs", {}).values():
        pid = info.get("pid")
        if not pid:
            continue
        try:
            if os.name == "nt":  # Windows : arreter le processus et ses enfants
                subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True)
            else:
                os.killpg(os.getpgid(pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            pass


# --------------------------------------------------------------- commandes
def cmd_start(_):
    state = load_state()
    if state and any(is_up(i["port"]) for i in state["labs"].values()):
        sys.exit("Un examen est deja en cours. Utilisez `python exam.py reset` pour repartir de zero.")
    STATE_DIR.mkdir(exist_ok=True)
    (STATE_DIR / "logs").mkdir(exist_ok=True)

    labs_state = {}
    for lab_id, lab in LABS.items():
        flag = "FLAG{" + secrets.token_hex(8) + "}"
        env = dict(os.environ)
        env[f"FLAG_{lab_id.upper()}"] = flag
        env["PORT"] = str(lab["port"])
        log = open(STATE_DIR / "logs" / f"{lab_id}.log", "w")
        if os.name == "nt":
            detach = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        else:
            detach = {"start_new_session": True}
        proc = subprocess.Popen(
            [sys.executable, str(ROOT / "labs" / lab["dir"] / "app.py")],
            cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, **detach,
        )
        labs_state[lab_id] = {"sha256": sha(flag), "pid": proc.pid, "port": lab["port"], "solved_at": None}

    deadline = time.time() + 15
    while time.time() < deadline and not all(is_up(i["port"]) for i in labs_state.values()):
        time.sleep(0.3)

    state = {"started_at": time.time(), "duration_s": DURATION_S, "labs": labs_state}
    save_state(state)

    print(f"\n=== EXAMEN DEMARRE : {fmt(DURATION_S)} pour la partie CTF ===\n")
    for lab_id, lab in LABS.items():
        up = "OK " if is_up(lab["port"]) else "KO "
        print(f"[{up}] {lab_id}  http://127.0.0.1:{lab['port']}   {lab['title']}")
        print(f"        {lab['goal']}")
    print("\nRegles : boite noire pendant l'exploitation (ne lisez pas labs/*/app.py avant d'avoir le flag).")
    print("Soumission : python exam.py submit lab1 FLAG{...}")
    print("Bon courage !")


def cmd_status(_):
    state = load_state()
    if not state:
        sys.exit("Aucun examen en cours. Lancez `python exam.py start`.")
    remaining = state["started_at"] + state["duration_s"] - time.time()
    print(f"Temps restant : {fmt(remaining)}" + ("   (TEMPS ECOULE)" if remaining <= 0 else ""))
    for lab_id, info in state["labs"].items():
        flag = "flag OK" if info["solved_at"] else "flag a trouver"
        up = "en ligne" if is_up(info["port"]) else "arrete"
        print(f"  {lab_id}  :{info['port']}  {up:9}  {flag}")


def cmd_submit(args):
    state = load_state()
    if not state:
        sys.exit("Aucun examen en cours.")
    lab_id = norm_lab(args.lab)
    info = state["labs"][lab_id]
    if sha(args.flag) == info["sha256"]:
        if not info["solved_at"]:
            info["solved_at"] = time.time()
            save_state(state)
        elapsed = info["solved_at"] - state["started_at"]
        print(f"[OK] {lab_id} valide a T+{fmt(elapsed)}")
    else:
        print(f"[KO] flag incorrect pour {lab_id}")


def run_pytest(marker, test_file):
    cmd = [sys.executable, "-m", "pytest", "-q", "--tb=no", "-p", "no:cacheprovider",
           "-m", marker, test_file]
    res = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    return res.returncode, (res.stdout.strip().splitlines() or [""])[-1]


def cmd_grade(_):
    state = load_state()
    if not state:
        sys.exit("Aucun examen en cours.")
    used = time.time() - state["started_at"]
    print(f"Temps utilise : {fmt(used)} / {fmt(state['duration_s'])}\n")
    total = 0
    print(f"{'lab':6} {'flag(40)':9} {'patch(40)':10} {'rapport':8}  details")
    for lab_id in LABS:
        test_file = f"tests/test_{lab_id}.py"
        sec_rc, sec_line = run_pytest("security", test_file)
        fun_rc, fun_line = run_pytest("functional", test_file)
        flag_pts = 40 if state["labs"][lab_id]["solved_at"] else 0
        patch_ok = sec_rc == 0 and fun_rc == 0
        patch_pts = 40 if patch_ok else 0
        report = ROOT / "reports" / f"{lab_id}.md"
        has_report = report.exists() and report.stat().st_size > 200
        total += flag_pts + patch_pts
        detail = f"securite: {sec_line} | fonctionnel: {fun_line}"
        if sec_rc == 0 and fun_rc != 0:
            detail += "  <- le patch casse l'application (0 pt)"
        print(f"{lab_id:6} {flag_pts:<9} {patch_pts:<10} {'redige' if has_report else 'absent':8}  {detail}")
    print(f"\nTotal hors rapports : {total}/400  (rapports : 20 pts x 5, a faire corriger par Claude)")
    print("Note CTF provisoire (hors rapports) : "
          f"{total / 400 * 20:.1f}/20  -> note finale = 0.7 x CTF + 0.3 x QCM")


def cmd_stop(_):
    stop_labs(load_state())
    print("Labs arretes.")


def cmd_reset(_):
    stop_labs(load_state())
    if STATE_FILE.exists():
        STATE_FILE.unlink()
    print("Etat efface. `python exam.py start` pour recommencer.")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("start").set_defaults(fn=cmd_start)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    p = sub.add_parser("submit")
    p.add_argument("lab")
    p.add_argument("flag")
    p.set_defaults(fn=cmd_submit)
    sub.add_parser("grade").set_defaults(fn=cmd_grade)
    sub.add_parser("stop").set_defaults(fn=cmd_stop)
    sub.add_parser("reset").set_defaults(fn=cmd_reset)
    args = parser.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
