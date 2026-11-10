"""Test suite for cryptographic verification of external network security datasets.

Verifies:
1. Cryptographic SHA-256 integrity of all 18 acquired PCAP captures on external storage.
2. Exact match against .meta.json manifests, .sha256 checksum files, and dataset-registry.md.
3. Path traversal protection, malformed input handling, and tool_dataset_hash_verify MCP tool logic.
4. Companion artifact presence (Suricata EVE JSON, Zeek conn.log) and integrity.
"""

import hashlib
import json
import os
import re
import tempfile
import unittest

DATASETS_DIR = "/run/media/harshitgarg/Data1/NetGuard-datasets"
VERIFIED_DIR = os.path.join(DATASETS_DIR, "verified")
HASHES_DIR = os.path.join(DATASETS_DIR, "hashes")
REGISTRY_MD = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "docs", "evaluation", "dataset-registry.md")
)

# Canonical inventory of all 18 registered PCAPs
REGISTERED_DATASETS = [
    "foxit_log4shell",
    "foxit_quantum_insert",
    "iot23_honeypot_4_1",
    "iot23_malware_20_1",
    "iot23_malware_34_1",
    "iot23_malware_3_1",
    "iot23_malware_8_1",
    "m_rau5_icmp_tunnel",
    "nozomi_triton_exec",
    "oisf_modbus",
    "oisf_syn_flood",
    "oisf_tls_sni_anomaly",
    "ws_arp_storm",
    "ws_dns_remoteshell",
    "ws_http_browsing",
    "ws_nmap_stealth_scan",
    "ws_skype_irc",
    "ws_teardrop",
]


def is_dataset_volume_available() -> bool:
    """Check if external datasets volume is mounted and verified directory exists."""
    return os.path.ismount("/run/media/harshitgarg/Data1") and os.path.isdir(VERIFIED_DIR)


def compute_file_sha256(filepath: str, chunk_size: int = 65536) -> str:
    """Compute SHA-256 digest of a file in streaming chunks."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


class TestDatasetHashVerify(unittest.TestCase):
    """Test cryptographic integrity and verification mechanics."""

    def setUp(self):
        self.volume_available = is_dataset_volume_available()

    def test_pcap_mcp_tool_hash_verify_functionality(self):
        """Test tool_dataset_hash_verify in pcap_mcp_server with a local synthetic file."""
        import sys
        scripts_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", ".agents", "plugins", "netguard-workbench", "scripts")
        )
        if scripts_dir not in sys.path:
            sys.path.insert(0, scripts_dir)

        from pcap_mcp_server import tool_dataset_hash_verify

        payload = b"NetGuard Cryptographic Integrity Test Payload 2026\n"
        expected_sha256 = hashlib.sha256(payload).hexdigest()
        expected_md5 = hashlib.md5(payload).hexdigest()

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
            tf.write(payload)
            temp_path = tf.name

        try:
            # Test valid matching hash
            res = tool_dataset_hash_verify(temp_path, expected_sha256=expected_sha256)
            self.assertNotIn("error", res)
            self.assertEqual(res["sha256"], expected_sha256)
            self.assertEqual(res["md5"], expected_md5)
            self.assertEqual(res["file_size_bytes"], len(payload))
            self.assertTrue(res["matches_expected"])

            # Test mismatched hash
            res_mismatch = tool_dataset_hash_verify(temp_path, expected_sha256="0" * 64)
            self.assertNotIn("error", res_mismatch)
            self.assertFalse(res_mismatch["matches_expected"])

            # Test missing file
            res_missing = tool_dataset_hash_verify("/nonexistent/file/path/here.pcap")
            self.assertIn("error", res_missing)

            # Test path traversal prevention
            res_traversal = tool_dataset_hash_verify("../../../../../etc/shadow")
            self.assertIn("error", res_traversal)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

    def test_dataset_registry_markdown_has_all_18_entries(self):
        """Verify docs/evaluation/dataset-registry.md defines all 18 canonical dataset entries."""
        self.assertTrue(os.path.isfile(REGISTRY_MD), f"Registry file missing: {REGISTRY_MD}")
        with open(REGISTRY_MD, "r", encoding="utf-8") as f:
            content = f.read()

        for ds_id in REGISTERED_DATASETS:
            pattern = rf"`{re.escape(ds_id)}`"
            self.assertTrue(
                re.search(pattern, content),
                f"Dataset {ds_id} not found in {REGISTRY_MD}"
            )

    def test_all_18_checksum_files_match_registry(self):
        """Verify each .sha256 file matches the hash documented in dataset-registry.md."""
        if not self.volume_available:
            self.skipTest("Dataset storage volume /run/media/harshitgarg/Data1 not mounted.")

        with open(REGISTRY_MD, "r", encoding="utf-8") as f:
            registry_text = f.read()

        for ds_id in REGISTERED_DATASETS:
            sha_file = os.path.join(HASHES_DIR, f"{ds_id}.sha256")
            self.assertTrue(os.path.isfile(sha_file), f"Checksum file missing: {sha_file}")

            with open(sha_file, "r", encoding="utf-8") as f:
                line = f.read().strip()
                checksum = line.split()[0].lower()

            self.assertEqual(len(checksum), 64, f"Invalid SHA-256 length in {sha_file}")

            # Verify checksum appears in dataset-registry.md
            self.assertIn(
                checksum,
                registry_text.lower(),
                f"Digest {checksum} for {ds_id} does not appear in {REGISTRY_MD}"
            )

    def test_all_18_meta_manifests_match_checksum_files(self):
        """Verify each .meta.json file matches its corresponding .sha256 file."""
        if not self.volume_available:
            self.skipTest("Dataset storage volume /run/media/harshitgarg/Data1 not mounted.")

        for ds_id in REGISTERED_DATASETS:
            meta_file = os.path.join(VERIFIED_DIR, f"{ds_id}.meta.json")
            sha_file = os.path.join(HASHES_DIR, f"{ds_id}.sha256")

            self.assertTrue(os.path.isfile(meta_file), f"Metadata manifest missing: {meta_file}")
            self.assertTrue(os.path.isfile(sha_file), f"Checksum file missing: {sha_file}")

            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
            with open(sha_file, "r", encoding="utf-8") as f:
                expected_sha = f.read().strip().split()[0].lower()

            self.assertEqual(
                meta["sha256"].lower(),
                expected_sha,
                f"Hash in {meta_file} ({meta['sha256']}) does not match {sha_file} ({expected_sha})"
            )

    def test_all_18_pcaps_cryptographic_hashes(self):
        """Stream and compute SHA-256 for all 18 PCAPs on /dev/sdb1 and assert exact match."""
        if not self.volume_available:
            self.skipTest("Dataset storage volume /run/media/harshitgarg/Data1 not mounted.")

        for ds_id in REGISTERED_DATASETS:
            pcap_file = os.path.join(VERIFIED_DIR, f"{ds_id}.pcap")
            sha_file = os.path.join(HASHES_DIR, f"{ds_id}.sha256")
            meta_file = os.path.join(VERIFIED_DIR, f"{ds_id}.meta.json")

            self.assertTrue(os.path.isfile(pcap_file), f"PCAP missing: {pcap_file}")
            with open(sha_file, "r", encoding="utf-8") as f:
                expected_sha = f.read().strip().split()[0].lower()
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)

            # Compute actual SHA-256
            actual_sha = compute_file_sha256(pcap_file)
            actual_size = os.path.getsize(pcap_file)

            self.assertEqual(
                actual_sha,
                expected_sha,
                f"Cryptographic hash mismatch for {ds_id}: computed {actual_sha} vs expected {expected_sha}"
            )
            self.assertEqual(
                actual_size,
                meta["size_bytes"],
                f"File size mismatch for {ds_id}: actual {actual_size} vs meta {meta['size_bytes']}"
            )

    def test_companion_telemetry_artifacts_integrity(self):
        """Verify presence and non-zero size of companion Suricata and Zeek telemetry."""
        if not self.volume_available:
            self.skipTest("Dataset storage volume /run/media/harshitgarg/Data1 not mounted.")

        eve_json = os.path.join(VERIFIED_DIR, "iot23_malware_34_1_suricata_eve.json")
        zeek_log = os.path.join(VERIFIED_DIR, "iot23_malware_34_1_zeek_conn.log")

        self.assertTrue(os.path.isfile(eve_json), f"Suricata EVE JSON missing: {eve_json}")
        self.assertTrue(os.path.isfile(zeek_log), f"Zeek conn.log missing: {zeek_log}")

        self.assertGreater(os.path.getsize(eve_json), 1_000_000, "Suricata EVE JSON unexpectedly small")
        self.assertGreater(os.path.getsize(zeek_log), 1_000_000, "Zeek conn.log unexpectedly small")
