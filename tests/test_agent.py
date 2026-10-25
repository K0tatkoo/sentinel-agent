"""
Tests for sentinel-agent.

    python3 -m unittest discover -s tests -v

Nothing here reaches sudo, systemd, Docker, a BMC or the internet: `run` is
replaced by a recorder, the kernel's files are recorded trees under fixtures/,
and the network checks talk to little servers started inside the tests. What
the sudo tests prove is that every command the agent hands to sudo is one the
generated rules allow, word for word — sudo matches literally, so an argv that
drifts from the rules is refused on a real server.
"""
import http.server
import importlib.machinery
import importlib.util
import io
import json
import os
import re
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX = os.path.join(HERE, "fixtures")


def load():
    path = os.path.join(ROOT, "sentinel-agent")
    loader = importlib.machinery.SourceFileLoader("sentinel_agent", path)
    spec = importlib.util.spec_from_loader("sentinel_agent", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


agent = load()


def fixture(*parts):
    with open(os.path.join(FIX, *parts)) as fh:
        return fh.read()


def config(**over):
    """A config the way conf() would build it from a file holding `over`."""
    path = os.path.join(tempfile.mkdtemp(), "sentinel-agent.conf")
    with open(path, "w") as fh:
        json.dump(over, fh)
    return agent.conf(path)


class Recorder:
    """Stands in for `run`: remembers every argv and answers from a script."""

    def __init__(self, answers=None):
        self.calls = []
        self.answers = dict(answers or {})

    def __call__(self, args, timeout=10):
        self.calls.append(list(args))
        for prefix, answer in self.answers.items():
            if tuple(args[:len(prefix)]) == prefix:
                return answer(args) if callable(answer) else answer
        if len(args) > 1 and args[1] == "show":
            units = [a for a in args if a.endswith(".service")]
            return 0, "\n\n".join(f"Id={u}\nActiveState=active\nSubState=running\nUnitFileState=enabled" for u in units), ""
        return 0, "", ""

    def sudo_calls(self):
        return [c[2:] for c in self.calls if c[:2] == ["sudo", "-n"]]


class AgentCase(unittest.TestCase):
    def setUp(self):
        self.rec = Recorder()
        saved = (agent.run, agent.time.sleep, agent.STATE_DIR, agent.SYS, agent.PROC)
        agent.run = self.rec
        agent.time.sleep = lambda s: None
        agent.STATE_DIR = tempfile.mkdtemp()
        agent.SYS = os.path.join(FIX, "vm", "sys")
        agent.PROC = os.path.join(FIX, "proc")

        def restore():
            agent.run, agent.time.sleep, agent.STATE_DIR, agent.SYS, agent.PROC = saved
        self.addCleanup(restore)


# --------------------------------------------------------------------------- #
# kernel sensors
# --------------------------------------------------------------------------- #

class TestKernelSensors(AgentCase):
    def test_the_r620s_two_sockets_are_told_apart(self):
        agent.SYS = os.path.join(FIX, "r620", "sys")
        temps, fans, err = agent.kernel_sensors()
        self.assertIsNone(err)
        self.assertEqual(len(temps), 14)
        labels = [t["label"] for t in temps]
        self.assertIn("CPU 1 · Package id 0", labels)
        self.assertIn("CPU 2 · Core 5", labels)
        self.assertEqual(len(set(labels)), 14, "every label must be unique")
        pkg = next(t for t in temps if t["label"] == "CPU 1 · Package id 0")
        self.assertEqual((pkg["celsius"], pkg["warn"], pkg["crit"], pkg["group"]), (49.0, 63.0, 73.0, "cpu"))
        self.assertEqual(fans, [])

    def test_the_zone_is_not_read_twice_when_hwmon_has_it(self):
        agent.SYS = os.path.join(FIX, "r620", "sys")       # also has x86_pkg_temp as a zone
        temps, _f, _e = agent.kernel_sensors()
        self.assertFalse(any(t["label"] == "x86_pkg_temp" for t in temps))

    def test_a_pi_5(self):
        agent.SYS = os.path.join(FIX, "pi5", "sys")
        temps, fans, _e = agent.kernel_sensors()
        self.assertEqual([(t["label"], t["group"], t["celsius"]) for t in temps], [("cpu_thermal 1", "cpu", 47.9)])

    def test_an_old_pi_kernel_falls_back_to_the_thermal_zone(self):
        agent.SYS = os.path.join(FIX, "pi-zone-only", "sys")
        temps, _f, _e = agent.kernel_sensors()
        self.assertEqual(len(temps), 1)
        t = temps[0]
        self.assertEqual((t["label"], t["group"], t["celsius"], t["warn"]), ("cpu-thermal", "cpu", 52.1, 85.0))

    def test_a_laptop(self):
        agent.SYS = os.path.join(FIX, "laptop", "sys")
        temps, fans, _e = agent.kernel_sensors()
        by = {t["label"]: t for t in temps}
        self.assertEqual(by["nvme0 · Composite"]["group"], "drive")
        self.assertEqual(by["nvme0 · Composite"]["crit"], 84.8)
        self.assertEqual(by["Tctl"]["group"], "cpu")
        self.assertEqual(by["acpitz 1"]["group"], "board")
        # The empty fan header (0 RPM) is left out; the real fan stays.
        self.assertEqual([(f["label"], f["rpm"]) for f in fans], [("Fan 1", 2900)])

    def test_a_vm_has_nothing_and_says_nothing(self):
        temps, fans, err = agent.kernel_sensors()
        self.assertEqual((temps, fans, err), ([], [], None))


class TestModel(AgentCase):
    def test_dell(self):
        agent.SYS = os.path.join(FIX, "r620", "sys")
        self.rec.answers[("/usr/bin/systemd-detect-virt",)] = (1, "none\n", "")
        self.assertEqual(agent.model(config()), {"vendor": "Dell Inc.", "name": "PowerEdge R620", "virt": None})

    def test_a_pi_names_itself_in_the_device_tree(self):
        agent.SYS = os.path.join(FIX, "pi5", "sys")
        agent.PROC = os.path.join(FIX, "pi5", "proc")
        m = agent.model(config())
        self.assertEqual(m["name"], "Raspberry Pi 5 Model B Rev 1.0")

    def test_a_vm_says_so(self):
        self.rec.answers[("/usr/bin/systemd-detect-virt",)] = (0, "kvm\n", "")
        m = agent.model(config())
        self.assertEqual((m["vendor"], m["virt"]), ("QEMU", "kvm"))


# --------------------------------------------------------------------------- #
# BMC
# --------------------------------------------------------------------------- #

class TestSdr(unittest.TestCase):
    def test_the_r620_reads_as_it_always_has(self):
        detail, temps, fans = agent.parse_sdr(fixture("r620", "cmd", "ipmitool-sdr-elist.txt"))
        # Exactly what agent 1.2.0 produced, so the installed iPhone app sees no change.
        self.assertEqual(agent.summarize_bmc(detail), {
            "inlet_c": 34.0, "exhaust_c": 41.0, "cpu_max_c": 51.0, "fan_modules": 7, "fan_avg_rpm": 4226,
            "watts": 98.0, "redundancy": "Fully Redundant",
            "psus": [{"bay": 1, "volts": 230.0, "amps": 0.2, "watts": 49, "fault": False},
                     {"bay": 2, "volts": 230.0, "amps": 0.2, "watts": 49, "fault": False}]})
        self.assertEqual([t["label"] for t in temps], ["Inlet", "Exhaust", "CPU 1", "CPU 2"])
        self.assertTrue(all(t["status"] == "ok" for t in temps))
        self.assertEqual(len(fans), 14)
        self.assertEqual(fans[0], {"label": "Fan 1A", "rpm": 4320.0, "status": "ok", "source": "ipmi"})

    def test_supermicro(self):
        detail, temps, fans = agent.parse_sdr(fixture("ipmi", "supermicro.txt"))
        by = {t["label"]: t for t in temps}
        self.assertEqual(by["CPU 1"]["group"], "cpu")
        self.assertEqual(by["System"]["group"], "board")
        self.assertEqual(by["Peripheral"]["status"], "warn")            # the BMC's own non-critical
        fan2 = next(f for f in fans if f["label"] == "Fan 2")
        self.assertEqual((fan2["rpm"], fan2["status"]), (0.0, "crit"))  # a BMC's 0 is real: kept
        self.assertFalse(any(f["label"] == "FANA" and f["rpm"] is None for f in fans if f["rpm"] is not None))
        psus = {p["bay"]: p for p in detail["psus"]}
        self.assertFalse(psus[1]["fault"])
        self.assertTrue(psus[2]["fault"])

    def test_hpe(self):
        detail, temps, fans = agent.parse_sdr(fixture("ipmi", "hpe.txt"))
        by = {t["label"]: t for t in temps}
        self.assertEqual(by["Inlet"]["group"], "inlet")
        self.assertEqual(by["CPU 1 02-CPU 1"]["group"], "cpu")
        self.assertEqual(fans, [])                       # percent is not RPM
        self.assertEqual(detail["watts"], 275.0)
        self.assertEqual([p["watts"] for p in detail["psus"]], [145.0, 130.0])


# --------------------------------------------------------------------------- #
# SMART and GPUs
# --------------------------------------------------------------------------- #

class TestSmart(AgentCase):
    def test_kinds(self):
        sata = agent.parse_smart(fixture("smart", "sata.json"))
        self.assertEqual((sata["health"], sata["celsius"], sata["hours"], sata["realloc"], sata["pending"]),
                         ("passed", 33, 41022, 0, 8))
        nvme = agent.parse_smart(fixture("smart", "nvme.json"))
        self.assertEqual((nvme["wear_pct"], nvme["celsius"]), (3, 41))
        sas = agent.parse_smart(fixture("smart", "megaraid-sas.json"))
        self.assertEqual((sas["model"], sas["realloc"], sas["health"]), ("SEAGATE ST900MM0006", 0, "passed"))
        self.assertEqual(agent.parse_smart(fixture("smart", "standby.json")), {"state": "standby"})
        bad = agent.parse_smart(fixture("smart", "failing.json"))
        self.assertEqual((bad["health"], bad["realloc"], bad["pending"]), ("failed", 1688, 112))
        self.assertEqual(agent.parse_smart("smartctl 6.6 says hello")["state"], "error")

    def test_scan(self):
        devs = agent.parse_smart_scan(fixture("smart", "scan-open.txt"))
        self.assertEqual(devs, [{"dev": "/dev/sda", "type": "sat"}, {"dev": "/dev/nvme0", "type": "nvme"},
                                {"dev": "/dev/bus/0", "type": "megaraid,0"}, {"dev": "/dev/bus/0", "type": "megaraid,1"}])

    def test_a_sleeping_drive_keeps_its_last_reading_and_one_drive_per_poll(self):
        cfg = config(hardware={"smart": [{"dev": "/dev/sda", "type": "sat"}, {"dev": "/dev/sdb", "type": "sat"}]})
        reads = {"/dev/sda": fixture("smart", "sata.json"), "/dev/sdb": fixture("smart", "failing.json")}
        self.rec.answers[("sudo", "-n", "/usr/sbin/smartctl")] = lambda a: (0, reads[a[-1]], "")
        drives, err = agent.read_smart(cfg, "stalest")
        self.assertIsNone(err)
        self.assertEqual(len(drives), 1, "a poll pays for one drive, never all of them")
        drives, _ = agent.read_smart(cfg, "stalest")
        self.assertEqual(len(drives), 2)
        reads["/dev/sda"] = fixture("smart", "standby.json")
        for entry in ("/dev/sda", "/dev/sdb"):
            agent.cache_merge("smart", {entry: dict(agent.cache_get("smart")[entry], t=0)})
        drives, _ = agent.read_smart(cfg, "all")
        sda = next(d for d in drives if d["device"] == "/dev/sda")
        self.assertEqual((sda["state"], sda["celsius"], sda["health"]), ("standby", 33, "passed"))

    def test_megaraid_drives_keep_their_slot_in_the_name(self):
        self.assertEqual(agent._smart_id("/dev/bus/0", "megaraid,3"), "/dev/bus/0 [megaraid,3]")
        self.assertEqual(agent._smart_id("/dev/sda", "sat"), "/dev/sda")


class TestGpu(unittest.TestCase):
    def test_a_windows_capture_with_crlf(self):
        gpus = agent.parse_nvidia_smi(fixture("gpu", "nvidia-smi-4060ti.csv"))
        self.assertEqual(gpus, [{"index": 0, "name": "NVIDIA GeForce RTX 4060 Ti", "celsius": 58.0, "util_pct": 98.0,
                                 "mem_used_mb": 8671.0, "mem_total_mb": 16380.0, "watts": 140.9, "fan_pct": 31.0}])

    def test_no_fan_is_null_not_zero(self):
        gpus = agent.parse_nvidia_smi(fixture("gpu", "nvidia-smi-nofan.csv"))
        self.assertEqual([g["fan_pct"] for g in gpus], [None, None])
        self.assertEqual([g["index"] for g in gpus], [0, 1])


class TestHardwareBlock(AgentCase):
    def test_thresholds_from_the_config_win(self):
        agent.SYS = os.path.join(FIX, "r620", "sys")
        self.rec.answers[("sudo", "-n", "/usr/bin/ipmitool", "sdr")] = (0, fixture("r620", "cmd", "ipmitool-sdr-elist.txt"), "")
        cfg = config(hardware={"ipmi": True}, thresholds={"Inlet": {"warn": 42, "crit": 47}})
        hw = agent.hardware_block(cfg, "full", bmc=agent.read_bmc(cfg))
        inlet = next(t for t in hw["temps"] if t["label"] == "Inlet")
        self.assertEqual((inlet["warn"], inlet["crit"], inlet["source"]), (42.0, 47.0, "ipmi"))
        self.assertEqual(hw["watts"], 98.0)
        self.assertEqual(hw["sources"], {"sensors": None, "ipmi": None})

    def test_nvme_is_not_counted_twice(self):
        agent.SYS = os.path.join(FIX, "laptop", "sys")
        cfg = config(hardware={"smart": [{"dev": "/dev/nvme0", "type": "nvme"}]})
        self.rec.answers[("sudo", "-n", "/usr/sbin/smartctl")] = (0, fixture("smart", "nvme.json"), "")
        hw = agent.hardware_block(cfg, "full")
        drive_temps = [t for t in hw["temps"] if t["group"] == "drive"]
        self.assertEqual(len(drive_temps), 1, drive_temps)
        self.assertEqual(hw["drives"][0]["wear_pct"], 3)

    def test_a_missing_gpu_tool_is_an_error_for_that_source_only(self):
        cfg = config(hardware={"gpu": True})
        self.rec.answers[("/usr/bin/nvidia-smi",)] = (127, "", "/usr/bin/nvidia-smi: not found")
        hw = agent.hardware_block(cfg, "poll")
        self.assertEqual(hw["sources"], {"sensors": None, "gpu": "/usr/bin/nvidia-smi: not found"})


# --------------------------------------------------------------------------- #
# host
# --------------------------------------------------------------------------- #

class TestHost(AgentCase):
    def test_the_primary_interface_is_the_default_routes(self):
        self.assertEqual(agent.default_iface(), "eth0")            # metric 100 beats 600

    def test_the_host_block(self):
        agent.SYS = os.path.join(FIX, "proc-net-sys", "sys")
        h = agent.host_block(rates=True)
        self.assertEqual(h["primary_iface"], "eth0")
        self.assertEqual(h["mem"]["total_mb"], 7812)
        self.assertEqual([d["mount"] for d in h["disks"]], ["/"])   # no tmpfs, no loop devices
        self.assertEqual([n["iface"] for n in h["net"]], ["eth0"])         # eth1 has no counters: left out
        self.assertEqual(h["psi_cpu"], 0.5)
        brief = agent.host_block(rates=False)
        self.assertNotIn("cpu_pct", brief)
        self.assertNotIn("top", brief)


# --------------------------------------------------------------------------- #
# detection
# --------------------------------------------------------------------------- #

class TestDetection(unittest.TestCase):
    def test_a_generic_server(self):
        units = agent.classify_units(fixture("systemd", "ubuntu-show.txt"))
        self.assertEqual(units, [
            "ssh.service", "docker.service", "containerd.service", "nginx.service", "myapp.service",
            "tailscaled.service", "cloudflared.service", "postgresql.service", "postgresql@16-main.service",
            "redis-server.service", "php8.3-fpm.service", "jellyfin.service"])

    def test_debians_postgresql_oneshot_gives_way_to_its_clusters(self):
        units = ["nginx.service", "postgresql.service"]
        self.assertEqual(agent.postgres_clusters(units, ["postgresql@16-main.service", "nginx.service"]),
                         ["nginx.service", "postgresql@16-main.service"])
        self.assertEqual(agent.postgres_clusters(units, []), units)

    def test_check_arguments(self):
        self.assertEqual(agent.parse_check_arg("https://example.com/health"),
                         {"kind": "http", "url": "https://example.com/health", "label": "example.com"})
        self.assertEqual(agent.parse_check_arg("db.local:5432"), {"kind": "tcp", "host": "db.local", "port": 5432})
        self.assertEqual(agent.parse_check_arg("minecraft:127.0.0.1:25565"),
                         {"kind": "minecraft", "host": "127.0.0.1", "port": 25565})
        with self.assertRaises(ValueError):
            agent.parse_check_arg("nonsense")


class TestWriteConfig(unittest.TestCase):
    def setUp(self):
        self.path = os.path.join(tempfile.mkdtemp(), "sentinel-agent.conf")
        saved = agent.detect_paths
        agent.detect_paths = lambda: {"systemctl": "/usr/bin/systemctl", "docker": "/usr/bin/docker"}
        self.addCleanup(lambda: setattr(agent, "detect_paths", saved))
        self.detected = {"units": ["nginx.service", "ssh.service"], "containers": ["app"],
                         "hardware": {"sensors": True, "ipmi": False, "smart": [{"dev": "/dev/sda", "type": "sat"}], "gpu": False},
                         "paths": {"systemctl": "/usr/bin/systemctl"}, "notes": []}

    def test_a_fresh_install_is_read_only_with_nothing_controllable(self):
        c = agent.write_config(self.path, self.detected, [], None, fresh=True)
        self.assertEqual((c["allow_control"], c["control"]), (False, {"units": [], "containers": []}))
        self.assertEqual(c["units"], ["nginx.service", "ssh.service"])

    def test_allow_control_starts_from_what_is_watched(self):
        c = agent.write_config(self.path, self.detected, [], True, fresh=True)
        self.assertEqual(c["control"], {"units": ["nginx.service", "ssh.service"], "containers": ["app"]})
        cfg = agent.conf(self.path)
        self.assertEqual(agent.unit_verbs("ssh.service"), ["restart"])
        self.assertIn("ssh.service", agent.control_units(cfg))

    def test_detect_adds_and_never_removes(self):
        agent.write_config(self.path, self.detected, [], None, fresh=True)
        more = dict(self.detected, units=["nginx.service", "redis-server.service"], containers=[])
        c = agent.write_config(self.path, more, [{"kind": "tcp", "host": "h", "port": 1}], None, fresh=False)
        self.assertEqual(c["units"], ["nginx.service", "ssh.service", "redis-server.service"])
        self.assertEqual(c["containers"], ["app"])
        self.assertEqual(len(c["checks"]), 1)
        c = agent.write_config(self.path, None, [{"kind": "tcp", "host": "h", "port": 1}], None, fresh=False)
        self.assertEqual(len(c["checks"]), 1, "the same check is not added twice")

    def test_an_agent_1_config_keeps_its_controls_on_upgrade(self):
        with open(self.path, "w") as fh:
            json.dump({"allow_control": True, "units": ["mc.service", "ssh.service"], "containers": ["ark"],
                       "status_url": "http://127.0.0.1:3300/api/snapshot",
                       "games": {"mc": {"unit": "mc.service"}}}, fh)
        saved = agent.detect_hardware
        agent.detect_hardware = lambda paths, notes: {"sensors": True, "ipmi": True, "smart": [], "gpu": False}
        self.addCleanup(lambda: setattr(agent, "detect_hardware", saved))
        c = agent.write_config(self.path, None, [], None, fresh=False)
        self.assertEqual(c["control"], {"units": ["mc.service", "ssh.service"], "containers": ["ark"]})
        self.assertTrue(c["hardware"]["ipmi"], "an upgrade finds the BMC agent 1.x read without being told")
        self.assertEqual(c["paths"]["docker"], "/usr/bin/docker")
        cfg = agent.conf(self.path)
        self.assertEqual([ch["kind"] for ch in agent.check_specs(cfg)], ["dashboard"])
        self.assertEqual(agent.protocol1_controls(cfg), {"mc": ["restart", "start", "stop"]})


# --------------------------------------------------------------------------- #
# controls
# --------------------------------------------------------------------------- #

def control_config(**over):
    base = dict(allow_control=True,
                units=["nginx.service", "ssh.service", "mc.service", "tailscaled.service"],
                containers=["web", "game"],
                control={"units": ["nginx.service", "ssh.service", "mc.service", "tailscaled.service"],
                         "containers": ["web", "game"]},
                checks=[{"key": "mc", "kind": "minecraft", "host": "127.0.0.1", "port": 25565,
                         "control": {"unit": "mc.service", "hints": {"start": "about a minute"}}},
                        {"key": "big", "kind": "tcp", "host": "127.0.0.1", "port": 7777,
                         "control": {"container": "game",
                                     "commands": {"start": ["/usr/bin/true", "wake"], "stop": ["/usr/bin/true", "off"],
                                                  "sleep": ["/usr/bin/true", "sleep"], "bogus": ["relative/path"]}}}])
    base.update(over)
    return config(**base)


class TestControls(AgentCase):
    def test_a_lifeline_can_be_restarted_but_never_stopped(self):
        cfg = control_config()
        r = agent.cmd_action(cfg, ["stop", "ssh.service"])
        self.assertFalse(r["ok"])
        self.assertIn("only be restarted", r["error"])
        self.assertEqual(self.rec.sudo_calls(), [])
        self.assertTrue(agent.cmd_action(cfg, ["restart", "ssh.service"])["ok"])
        self.assertTrue(agent.cmd_action(cfg, ["stop", "nginx.service"])["ok"])
        self.assertEqual(self.rec.sudo_calls(), [["/usr/bin/systemctl", "restart", "ssh.service"],
                                                 ["/usr/bin/systemctl", "stop", "nginx.service"]])

    def test_watched_is_not_controllable(self):
        cfg = control_config(control={"units": ["nginx.service"], "containers": []})
        self.assertFalse(agent.cmd_action(cfg, ["restart", "mc.service"])["ok"])
        self.assertFalse(agent.cmd_daction(cfg, ["restart", "web"])["ok"])

    def test_nothing_without_allow_control(self):
        cfg = control_config(allow_control=False)
        self.assertFalse(agent.cmd_action(cfg, ["restart", "nginx.service"])["ok"])
        self.assertFalse(agent.cmd_check(cfg, ["start", "mc"])["ok"])
        self.assertEqual(agent.protocol1_controls(cfg), {})
        self.assertEqual(agent.sudo_argvs(cfg), [k for k in agent.sudo_argvs(cfg) if k[0] == "read"])

    def test_a_checks_container_is_only_ever_moved_through_the_check(self):
        cfg = control_config()
        r = agent.cmd_daction(cfg, ["stop", "game"])
        self.assertFalse(r["ok"])
        self.assertIn("use its controls", r["error"])
        self.assertNotIn("game", agent.control_containers(cfg))
        argvs = [a for _k, a in agent.sudo_argvs(cfg)]
        self.assertNotIn(["/usr/bin/docker", "stop", "game"], argvs)

    def test_check_controls(self):
        cfg = control_config()
        self.assertEqual(agent.protocol1_controls(cfg), {"big": ["sleep", "start", "stop"], "mc": ["restart", "start", "stop"]})
        self.assertTrue(agent.cmd_check(cfg, ["stop", "mc"])["ok"])
        self.assertTrue(agent.cmd_check(cfg, ["sleep", "big"])["ok"])
        self.assertTrue(agent.cmd_check(cfg, ["start", "big"])["ok"])
        self.assertFalse(agent.cmd_check(cfg, ["bogus", "big"])["ok"])
        self.assertFalse(agent.cmd_check(cfg, ["restart", "big"])["ok"])      # not configured
        self.assertEqual(self.rec.sudo_calls(), [["/usr/bin/systemctl", "disable", "--now", "mc.service"],
                                                 ["/usr/bin/true", "sleep"], ["/usr/bin/true", "wake"]])
        self.assertTrue(agent.cmd_game(cfg, ["start", "mc"])["ok"] if hasattr(agent, "cmd_game") else agent.COMMANDS["game"](cfg, ["start", "mc"])["ok"])

    def test_a_command_must_be_a_root_owned_absolute_file(self):
        self.assertTrue(agent._valid_command(["/usr/bin/true", "x"]))
        self.assertFalse(agent._valid_command(["true", "x"]))
        self.assertFalse(agent._valid_command(["/usr/bin/true", "two words"]))
        self.assertFalse(agent._valid_command(["/usr/bin/true", "*"]))
        tmp = tempfile.NamedTemporaryFile(delete=False)
        self.addCleanup(lambda: os.unlink(tmp.name))
        if os.getuid() != 0:
            self.assertFalse(agent._valid_command([tmp.name]), "a file the agent's own account owns is not trusted")


# --------------------------------------------------------------------------- #
# the sudo rules
# --------------------------------------------------------------------------- #

def parse_sudoers(text):
    """The commands a drop-in allows, unescaped, as 'path arg arg' strings."""
    text = text.replace("\\\n", " ")
    allowed = set()
    for line in text.splitlines():
        m = re.match(r"^Cmnd_Alias\s+\w+\s*=\s*(.*)$", line)
        if not m:
            continue
        for cmd in re.split(r"(?<!\\),", m.group(1)):
            cmd = re.sub(r"\s+", " ", cmd.strip())
            cmd = re.sub(r"\\(.)", r"\1", cmd)
            if cmd.endswith(' ""'):
                cmd = cmd[:-3]
            allowed.add(cmd)
    return allowed


class TestSudoers(AgentCase):
    def full_config(self):
        return control_config(
            units=["nginx.service", "ssh.service", "mc.service", "tailscaled.service", "foo@bar:1.service"],
            hardware={"sensors": True, "ipmi": True, "gpu": True,
                      "smart": [{"dev": "/dev/sda", "type": "sat"}, {"dev": "/dev/bus/0", "type": "megaraid,0"}]})

    def exercise(self, cfg):
        """Every handler that can reach sudo, with arguments that pass."""
        self.rec.answers[("sudo", "-n", "/usr/bin/docker", "ps")] = (0, '{"Names":"web","State":"running","Status":"Up"}\n{"Names":"game","State":"exited"}', "")
        agent.cmd_snapshot(cfg, [])
        agent.cmd_hw(cfg, [])
        agent.cmd_sel(cfg, ["5"])
        for u in cfg["units"]:
            agent.cmd_logs(cfg, [u, "50"])
        for c in cfg["containers"]:
            agent.cmd_dlogs(cfg, [c, "50"])
        for u in agent.control_units(cfg):
            for v in agent.unit_verbs(u):
                agent.cmd_action(cfg, [v, u])
        for c in agent.control_containers(cfg):
            for v in agent.ACTIONS:
                agent.cmd_daction(cfg, [v, c])
        for key in agent.check_control_specs(cfg):
            for v in agent.check_control(cfg, key)[0]:
                agent.cmd_check(cfg, [v, key])

    def test_every_sudo_call_is_allowed_word_for_word(self):
        cfg = self.full_config()
        allowed = parse_sudoers(agent.sudoers_text(cfg, "sentinel", quiet_logs=True))
        self.exercise(cfg)
        calls = self.rec.sudo_calls()
        self.assertGreater(len(calls), 20)
        for argv in calls:
            self.assertIn(" ".join(argv), allowed, f"sudo would refuse: {argv}")

    def test_the_rules_hold_nothing_but_exact_commands(self):
        cfg = self.full_config()
        text = agent.sudoers_text(cfg, "sentinel", quiet_logs=True)
        self.assertNotIn("*", text)
        self.assertNotIn("ALL=(root) NOPASSWD: ALL", text)
        self.assertIn("megaraid\\,0", text, "the comma must be escaped or the rule splits in two")
        self.assertIn("foo@bar\\:1.service", text)
        self.assertIn("/usr/bin/ipmitool sel elist last 200", text)
        self.assertIn("-n 500", text)
        self.assertIn("Defaults!SENTINEL_READ !log_allowed", text)
        allowed = parse_sudoers(text)
        self.assertNotIn("/usr/bin/systemctl stop ssh.service", allowed)
        self.assertNotIn("/usr/bin/systemctl stop tailscaled.service", allowed)
        self.assertIn("/usr/bin/systemctl restart ssh.service", allowed)
        self.assertNotIn("relative/path", text)

    def test_no_arguments_is_written_as_empty_not_as_any(self):
        self.assertEqual(agent.sudo_command(["/usr/local/bin/x"]), '/usr/local/bin/x ""')

    def test_a_read_only_install_has_no_control_rules(self):
        cfg = self.full_config()
        cfg["allow_control"] = False
        text = agent.sudoers_text(cfg, "sentinel", quiet_logs=False)
        self.assertNotIn("SENTINEL_CONTROL", text)
        self.assertNotIn("log_allowed", text)

    def test_visudo_accepts_it(self):
        visudo = agent.which("visudo")
        if not visudo:
            self.skipTest("no visudo here")
        cfg = self.full_config()
        for quiet in (False, True):
            with tempfile.NamedTemporaryFile("w", suffix=".sudoers", delete=False) as fh:
                fh.write(agent.sudoers_text(cfg, "sentinel", quiet_logs=quiet))
            self.addCleanup(lambda p=fh.name: os.unlink(p))
            p = subprocess.run([visudo, "-cqf", fh.name], capture_output=True, text=True)
            if quiet and p.returncode != 0 and "log_allowed" in (p.stderr + p.stdout):
                continue                     # an old sudo: the installer falls back to the logged form
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_user_names_are_held_to_shape(self):
        with self.assertRaises(ValueError):
            agent.sudoers_text(config(), "root ALL=(ALL) ALL #")


# --------------------------------------------------------------------------- #
# checks, against real little servers
# --------------------------------------------------------------------------- #

class _Http(http.server.BaseHTTPRequestHandler):
    routes = {}

    def do_GET(self):
        code, body = self.routes.get(self.path, (404, b"nope"))
        self.send_response(code)
        self.send_header("Content-Type", "application/json" if body.startswith(b"{") else "text/plain")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def serve_http(routes):
    _Http.routes = routes
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Http)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    stop = srv.shutdown

    def shutdown():
        stop()
        srv.server_close()
    srv.shutdown = shutdown
    return srv


def serve_minecraft(status):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def handle():
        conn, _ = srv.accept()
        with conn:
            conn.settimeout(3)
            agent._read_exact(conn, agent._read_varint(conn))     # handshake
            agent._read_exact(conn, agent._read_varint(conn))     # status request
            body = json.dumps(status).encode()
            pkt = b"\x00" + agent._varint(len(body)) + body
            conn.sendall(agent._varint(len(pkt)) + pkt)
        srv.close()
    threading.Thread(target=handle, daemon=True).start()
    return srv.getsockname()[1]


def serve_a2s(name, map_, online, max_):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))

    def handle():
        data, addr = s.recvfrom(1400)
        s.sendto(b"\xFF\xFF\xFF\xFFA\x01\x02\x03\x04", addr)          # challenge first
        data, addr = s.recvfrom(1400)
        assert data.endswith(b"\x01\x02\x03\x04")
        body = (b"\xFF\xFF\xFF\xFFI\x11" + name.encode() + b"\x00" + map_.encode() + b"\x00rust\x00Rust\x00"
                + struct.pack("<H", 0) + bytes([online, max_, 0]) + b"dlp\x00" + b"2580\x00")
        s.sendto(body, addr)
        s.close()
    threading.Thread(target=handle, daemon=True).start()
    return s.getsockname()[1]


class TestChecks(AgentCase):
    def test_http(self):
        srv = serve_http({"/ok": (200, b"hello world"), "/down": (503, b"busy")})
        self.addCleanup(srv.shutdown)
        port = srv.server_address[1]
        ok = agent.run_check({"key": "a", "kind": "http", "url": f"http://127.0.0.1:{port}/ok", "contains": "world"})
        self.assertEqual((ok["up"], ok["state"], ok["detail"]["code"]), (True, "up", 200))
        self.assertIsNotNone(ok["ms"])
        down = agent.run_check({"key": "b", "kind": "http", "url": f"http://127.0.0.1:{port}/down"})
        self.assertEqual((down["up"], down["error"]), (False, "HTTP 503"))
        text = agent.run_check({"key": "c", "kind": "http", "url": f"http://127.0.0.1:{port}/ok", "contains": "missing"})
        self.assertEqual((text["up"], text["error"]), (False, "the expected text is not on the page"))

    def test_tcp_refused(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        r = agent.run_check({"key": "t", "kind": "tcp", "host": "127.0.0.1", "port": port})
        self.assertEqual((r["up"], r["error"]), (False, "connection refused"))

    def test_minecraft(self):
        port = serve_minecraft({"version": {"name": "1.21.10"}, "players": {"online": 2, "max": 20},
                                "description": {"text": "§aHello", "extra": [{"text": " world"}]}})
        r = agent.run_check({"key": "mc", "kind": "minecraft", "host": "127.0.0.1", "port": port})
        self.assertTrue(r["up"], r["error"])
        self.assertEqual(r["detail"], {"online": 2, "max": 20, "version": "1.21.10", "motd": "Hello world"})

    def test_a2s_with_a_challenge(self):
        port = serve_a2s("My Rust", "Procedural Map", 7, 50)
        r = agent.run_check({"key": "rust", "kind": "a2s", "host": "127.0.0.1", "port": port})
        self.assertTrue(r["up"], r["error"])
        self.assertEqual((r["label"], r["detail"]["online"], r["detail"]["max"], r["detail"]["map"]),
                         ("My Rust", 7, 50, "Procedural Map"))

    def test_results_are_reused_until_the_interval(self):
        srv = serve_http({"/": (200, b"x")})
        self.addCleanup(srv.shutdown)
        cfg = config(checks=[{"kind": "http", "url": f"http://127.0.0.1:{srv.server_address[1]}/"}])
        first = agent.all_checks(cfg)
        self.assertEqual(len(first), 1)
        self.assertTrue(first[0]["up"])
        srv.shutdown()
        again = agent.all_checks(cfg)
        self.assertEqual(again[0]["checked"], first[0]["checked"])
        self.assertTrue(again[0]["up"], "a result younger than the interval is reused")

    def test_the_dashboard_becomes_checks_and_the_protocol_1_fields(self):
        dash = {"games": [{"key": "ark", "label": "ARK", "up": False, "state": "sleeping", "hint": "join to wake it"},
                          {"key": "mc", "label": "Minecraft", "up": True, "online": 3, "max": 20}],
                "sites": [{"key": "Store", "label": "Store", "ok": True, "url": "https://example.com"}],
                "hw": {"inlet_c": 22, "fan_avg_rpm": 4000, "watts": 120}}
        srv = serve_http({"/api/snapshot": (200, json.dumps(dash).encode())})
        self.addCleanup(srv.shutdown)
        cfg = config(status_url=f"http://127.0.0.1:{srv.server_address[1]}/api/snapshot",
                     units=["mc.service"], allow_control=True, hardware={"ipmi": True},
                     games={"mc": {"unit": "mc.service"},
                            "ark": {"container": "ark", "hints": {"start": "about 6 minutes"},
                                    "commands": {"start": ["/usr/bin/true", "wake"], "sleep": ["/usr/bin/true", "sleep"],
                                                 "stop": ["/usr/bin/true", "off"], "restart": ["/usr/bin/true", "restart"]}}})
        checks = {c["key"]: c for c in agent.cmd_checks(cfg, [])["checks"]}
        self.assertEqual(checks["ark"]["state"], "sleeping")
        self.assertEqual(checks["ark"]["controls"], ["restart", "sleep", "start", "stop"])
        self.assertEqual(checks["ark"]["container"], "ark")
        self.assertEqual(checks["ark"]["hints"], {"start": "about 6 minutes"})
        self.assertEqual(checks["mc"]["detail"]["online"], 3)
        self.assertEqual(checks["store"]["kind"], "site")
        snap = agent.cmd_snapshot(cfg, [])
        self.assertEqual([g["key"] for g in snap["games"]], ["ark", "mc"])
        self.assertEqual(snap["controls"], {"ark": ["restart", "sleep", "start", "stop"], "mc": ["restart", "start", "stop"]})
        self.assertEqual(snap["hw_source"], "status")
        self.assertIsNone(snap["status_error"])
        inlet = next(t for t in snap["hardware"]["temps"] if t["label"] == "Inlet")
        self.assertEqual(inlet["celsius"], 22.0)
        self.assertFalse(any(c[:4] == ["sudo", "-n", "/usr/bin/ipmitool", "sdr"] for c in self.rec.calls),
                         "with a dashboard reading the BMC, the agent does not read it a second time")


# --------------------------------------------------------------------------- #
# the commands as a whole
# --------------------------------------------------------------------------- #

class TestCommands(AgentCase):
    def setUp(self):
        super().setUp()
        agent.SYS = os.path.join(FIX, "proc-net-sys", "sys")

    def test_snapshot_keeps_every_protocol_1_field(self):
        snap = agent.cmd_snapshot(config(units=["nginx.service"]), [])
        for k in ("ok", "version", "protocol", "time", "control", "controls", "host", "hw", "hw_error", "hw_source",
                  "services", "docker", "games", "sites", "status_error"):
            self.assertIn(k, snap)
        self.assertEqual(snap["protocol"], 2)
        self.assertIsNone(snap["status_error"], "no dashboard, no dashboard error")
        self.assertIsNone(snap["hw_error"], "no BMC, no BMC error")
        self.assertEqual(snap["services"][0]["unit"], "nginx.service")
        self.assertIn("cpu_pct", snap["host"])

    def test_brief_skips_the_slow_parts_and_brings_the_checks(self):
        cfg = config(containers=["web"])
        self.rec.answers[("sudo", "-n", "/usr/bin/docker", "ps")] = (0, '{"Names":"web","State":"running","Status":"Up"}', "")
        b = agent.cmd_brief(cfg, [])
        self.assertNotIn("cpu_pct", b["host"])
        self.assertIn("checks", b)
        self.assertFalse(any("stats" in c for c in self.rec.calls), "no docker stats in brief")

    def test_ping(self):
        p = agent.cmd_ping(config(checks=[{"kind": "tcp", "host": "h", "port": 1}]), [])
        self.assertEqual((p["protocol"], p["features"]), (2, ["checks", "sensors"]))

    def test_a_missing_container_is_shown_as_missing(self):
        cfg = config(containers=["gone"])
        self.rec.answers[("sudo", "-n", "/usr/bin/docker", "ps")] = (0, '{"Names":"other","State":"running"}', "")
        block, unwatched = agent.containers(cfg, cfg["containers"])
        self.assertEqual((block["list"][0]["state"], unwatched), ("missing", 1))

    def test_logs_fall_back_to_the_journal_groups(self):
        cfg = config(units=["nginx.service"])
        self.rec.answers[("sudo", "-n", "/usr/bin/journalctl")] = (1, "", "sudo: a password is required")
        self.rec.answers[("/usr/bin/journalctl",)] = (0, "\n".join(f"line {i}" for i in range(500)), "")
        r = agent.cmd_logs(cfg, ["nginx.service", "3"])
        self.assertEqual(r["lines"], ["line 497", "line 498", "line 499"])


class TestState(AgentCase):
    def test_concurrent_merges_lose_nothing(self):
        def worker(i):
            for j in range(20):
                agent.cache_merge("checks", {f"k{i}-{j}": {"v": j}})
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(agent.cache_get("checks")), 120)


class TestForcedCommand(unittest.TestCase):
    def run_agent(self, request, *argv):
        env = dict(os.environ, SSH_ORIGINAL_COMMAND=request)
        p = subprocess.run([sys.executable, os.path.join(ROOT, "sentinel-agent"), *argv],
                           capture_output=True, text=True, env=env, timeout=30)
        return json.loads(p.stdout.strip().splitlines()[-1])

    def test_the_admin_options_are_unreachable_through_ssh(self):
        r = self.run_agent("--sudoers --user root")
        self.assertFalse(r["ok"])
        self.assertIn("unknown subcommand", r["error"])

    def test_arguments_on_the_command_line_are_ignored_under_ssh(self):
        r = self.run_agent("bogus", "--write-config")
        self.assertIn("unknown subcommand 'bogus'", r["error"])

    def test_limits(self):
        self.assertIn("too many", self.run_agent("logs a b c d e")["error"])
        self.assertIn("parse", self.run_agent("logs 'unterminated")["error"])


if __name__ == "__main__":
    unittest.main()
