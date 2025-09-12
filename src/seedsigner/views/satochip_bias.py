import csv
import math
import os
import random
import time
import logging

from embit.util import secp256k1

from seedsigner.hardware.microsd import MicroSD
from seedsigner.helpers import seedkeeper_utils
from seedsigner.helpers.satochip_signer import _call_with_timeout
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.gui.screens import LargeIconStatusScreen, WarningScreen, RET_CODE__BACK_BUTTON
from seedsigner.gui.screens.screen import ButtonOption
from .view import View, Destination, MainMenuView, BackStackView

logger = logging.getLogger(__name__)


class ToolsSatochipBiasCheckView(View):
    """Run multiple signatures to look for ECDSA bias."""

    NUM_SAMPLES = 1000
    MAX_ATTEMPTS_FACTOR = 5
    MAX_CONSECUTIVE_FAILURES = 25

    @staticmethod
    def binom_z_p(n, k, p0=0.5):
        mu = n * p0
        sigma = (n * p0 * (1 - p0)) ** 0.5 or 1.0
        z = ((k - mu) - 0.5 if k / n >= p0 else (k - mu) + 0.5) / sigma
        p = 2 * (0.5 * (1 - math.erf(abs(z) / (2 ** 0.5))))
        return z, p

    @staticmethod
    def chi2_16(counts):
        exp = (sum(counts) / 16) if counts else 0
        chi2 = sum((c - exp) ** 2 / exp for c in counts if exp)
        status = "pass"
        if chi2 > 30.578:
            status = "fail"
        elif chi2 > 24.996:
            status = "warn"
        return chi2, status

    @staticmethod
    def runs_test(bits):
        n = len(bits)
        n1 = sum(bits)
        n0 = n - n1
        if n0 == 0 or n1 == 0:
            return float("inf"), 0.0
        runs = 1 + sum(bits[i] != bits[i - 1] for i in range(1, n))
        mu = 1 + 2 * n0 * n1 / n
        var = (2 * n0 * n1 * (2 * n0 * n1 - n)) / (n ** 2 * (n - 1))
        z = (runs - mu) / (var ** 0.5)
        p = 2 * (0.5 * (1 - math.erf(abs(z) / (2 ** 0.5))))
        return z, p

    def run(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread

        info_ret = self.run_screen(
            WarningScreen,
            title="Bias Test",
            status_headline=None,
            text="Test uses a limited number of signatures; an occasional failure is normal.",
            button_data=[ButtonOption("Run Test")],
            show_back_button=True,
        )
        if info_ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        connector = seedkeeper_utils.init_satochip(self, init_card_filter=["satochip"])
        if not connector:
            return Destination(BackStackView)

        timeout = self.settings.get_value(SettingsConstants.SETTING__SATOCHIP_SIGN_TIMEOUT)
        soft_threshold = timeout * 0.5
        hard_threshold = timeout
        transport = getattr(connector, "transport", "unknown")

        loading = LoadingScreenThread(text="Testing\n\n\n\n\n\n")
        loading.start()

        messages = set()
        msb_bits = []
        lsb_bits = []
        lsb4_counts = [0] * 16
        latencies = []
        csv_rows = []
        dropped = {"parse": 0, "duplicate": 0, "soft_timeout": 0, "hard_timeout": 0, "sw_error": 0, "exception": 0}

        max_attempts = self.NUM_SAMPLES * self.MAX_ATTEMPTS_FACTOR
        idx = 0
        consecutive_failures = 0
        while (
            len(msb_bits) < self.NUM_SAMPLES
            and idx < max_attempts
            and consecutive_failures < self.MAX_CONSECUTIVE_FAILURES
        ):
            tx_hash = os.urandom(32)
            if tx_hash in messages:
                csv_rows.append({"index": idx, "r_hex": "", "s_hex": "", "msb_r": "", "lsb_r": "", "lsb4_bucket": "", "latency_ms": "", "dropped_reason": "duplicate"})
                dropped["duplicate"] += 1
                idx += 1
                consecutive_failures += 1
                continue
            messages.add(tx_hash)
            for attempt in range(2):
                time.sleep(random.uniform(0.01, 0.03))
                start = time.monotonic()
                try:
                    sig, sw1, sw2 = _call_with_timeout(
                        connector.card_sign_transaction_hash, timeout, 0xFF, list(tx_hash), None
                    )
                except Exception:
                    csv_rows.append({"index": idx, "r_hex": "", "s_hex": "", "msb_r": "", "lsb_r": "", "lsb4_bucket": "", "latency_ms": "", "dropped_reason": "exception"})
                    dropped["exception"] += 1
                    idx += 1
                    consecutive_failures += 1
                    break
                latency = time.monotonic() - start
                latency_ms = int(latency * 1000)
                if latency > hard_threshold:
                    csv_rows.append({"index": idx, "r_hex": "", "s_hex": "", "msb_r": "", "lsb_r": "", "lsb4_bucket": "", "latency_ms": latency_ms, "dropped_reason": "hard_timeout"})
                    dropped["hard_timeout"] += 1
                    idx += 1
                    consecutive_failures += 1
                    break
                if latency > soft_threshold:
                    csv_rows.append({"index": idx, "r_hex": "", "s_hex": "", "msb_r": "", "lsb_r": "", "lsb4_bucket": "", "latency_ms": latency_ms, "dropped_reason": "soft_timeout"})
                    dropped["soft_timeout"] += 1
                    idx += 1
                    consecutive_failures += 1
                    if attempt == 0:
                        continue
                    break
                if sw1 != 0x90 or sw2 != 0x00:
                    csv_rows.append({"index": idx, "r_hex": "", "s_hex": "", "msb_r": "", "lsb_r": "", "lsb4_bucket": "", "latency_ms": latency_ms, "dropped_reason": f"sw_{sw1:02x}{sw2:02x}"})
                    dropped["sw_error"] += 1
                    idx += 1
                    consecutive_failures += 1
                    break
                try:
                    sig_obj = secp256k1.ecdsa_signature_parse_der(bytes(sig))
                    compact = secp256k1.ecdsa_signature_serialize_compact(sig_obj)
                    r = int.from_bytes(compact[:32], "big")
                    s = int.from_bytes(compact[32:], "big")
                except Exception:
                    csv_rows.append({"index": idx, "r_hex": "", "s_hex": "", "msb_r": "", "lsb_r": "", "lsb4_bucket": "", "latency_ms": latency_ms, "dropped_reason": "parse"})
                    dropped["parse"] += 1
                    idx += 1
                    consecutive_failures += 1
                    break
                msb = 1 if r >= (1 << 255) else 0
                lsb = r & 1
                bucket = r & 0xF
                msb_bits.append(msb)
                lsb_bits.append(lsb)
                lsb4_counts[bucket] += 1
                latencies.append(latency_ms)
                csv_rows.append({"index": idx, "r_hex": f"{r:064x}", "s_hex": f"{s:064x}", "msb_r": msb, "lsb_r": lsb, "lsb4_bucket": bucket, "latency_ms": latency_ms, "dropped_reason": ""})
                idx += 1
                consecutive_failures = 0
                break

        loading.stop()

        total = len(msb_bits)
        msb_ones = sum(msb_bits)
        lsb_ones = sum(lsb_bits)
        if total:
            msb_pct = msb_ones / total
            lsb_pct = lsb_ones / total
            msb_z, msb_p = self.binom_z_p(total, msb_ones)
            lsb_z, lsb_p = self.binom_z_p(total, lsb_ones)
            msb_ci_low = msb_pct - 1.96 * (msb_pct * (1 - msb_pct) / total) ** 0.5
            msb_ci_high = msb_pct + 1.96 * (msb_pct * (1 - msb_pct) / total) ** 0.5
            lsb_ci_low = lsb_pct - 1.96 * (lsb_pct * (1 - lsb_pct) / total) ** 0.5
            lsb_ci_high = lsb_pct + 1.96 * (lsb_pct * (1 - lsb_pct) / total) ** 0.5
            chi2, chi_status = self.chi2_16(lsb4_counts)
            runs_z, runs_p = self.runs_test(lsb_bits)
        else:
            msb_pct = lsb_pct = 0
            msb_z = msb_p = lsb_z = lsb_p = 0
            msb_ci_low = msb_ci_high = lsb_ci_low = lsb_ci_high = 0
            chi2, chi_status = 0, "fail"
            runs_z = runs_p = 0

        def p_status(p):
            if p < 0.01:
                return "fail"
            elif p < 0.05:
                return "warn"
            return "pass"

        msb_status = p_status(msb_p)
        lsb_status = p_status(lsb_p)
        runs_status = p_status(runs_p)

        fail_reasons = []
        warn_reasons = []
        abort_reason = None

        if total < self.NUM_SAMPLES:
            abort_reason = "insufficient valid signatures"

        if msb_status == "fail":
            fail_reasons.append("MSB monobit")
        elif msb_status == "warn":
            warn_reasons.append("MSB monobit")
        if lsb_status == "fail":
            fail_reasons.append("LSB monobit")
        elif lsb_status == "warn":
            warn_reasons.append("LSB monobit")
        if runs_status == "fail":
            fail_reasons.append("runs test")
        elif runs_status == "warn":
            warn_reasons.append("runs test")
        if chi_status == "fail":
            fail_reasons.append("chi-square")
        elif chi_status == "warn":
            warn_reasons.append("chi-square")

        if dropped["hard_timeout"] > 0:
            fail_reasons.append("hard timeout")
        if dropped["soft_timeout"] > self.NUM_SAMPLES * 0.01:
            fail_reasons.append(">1% soft timeouts")
        if dropped["parse"] > 0:
            warn_reasons.append("parse errors")

        if abort_reason:
            final_status = "abort"
        elif fail_reasons:
            final_status = "fail"
        elif warn_reasons:
            final_status = "warn"
        else:
            final_status = "pass"

        reason_text = ""
        if abort_reason:
            reason_text = abort_reason
        elif final_status in ("fail", "warn"):
            reasons = fail_reasons if final_status == "fail" else warn_reasons
            reason_text = ", ".join(reasons)

        avg_latency = sum(latencies) / len(latencies) if latencies else 0

        csv_path = MicroSD.get_microsd_dir() / f"satochip_bias_{transport}.csv"
        txt_path = MicroSD.get_microsd_dir() / f"satochip_bias_{transport}.txt"
        try:
            csv_path.parent.mkdir(parents=True, exist_ok=True)
            with csv_path.open("w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["index", "r_hex", "s_hex", "msb_r", "lsb_r", "lsb4_bucket", "latency_ms", "dropped_reason"])
                for row in csv_rows:
                    writer.writerow([row.get("index"), row.get("r_hex"), row.get("s_hex"), row.get("msb_r"), row.get("lsb_r"), row.get("lsb4_bucket"), row.get("latency_ms"), row.get("dropped_reason")])
                f.flush()
                os.fsync(f.fileno())
        except Exception as e:
            logger.warning("Failed to write CSV: %s", e)

        lines = [
            f"Status: {final_status.upper()}" + (f" ({reason_text})" if reason_text else ""),
            f"Transport: {transport}",
            f"Samples: {total}/{self.NUM_SAMPLES}",
            f"MSB1: {msb_ones}/{total} ({msb_pct*100:.1f}%) z={msb_z:.2f} p={msb_p:.3g} CI[{msb_ci_low*100:.1f}%, {msb_ci_high*100:.1f}%]",
            f"LSB1: {lsb_ones}/{total} ({lsb_pct*100:.1f}%) z={lsb_z:.2f} p={lsb_p:.3g} CI[{lsb_ci_low*100:.1f}%, {lsb_ci_high*100:.1f}%]",
            f"LSB4 χ²: {chi2:.2f} ({chi_status})",
            f"Runs z={runs_z:.2f} p={runs_p:.3g}",
            f"Dropped: {sum(dropped.values())} (parse={dropped['parse']}, dup={dropped['duplicate']}, soft={dropped['soft_timeout']}, hard={dropped['hard_timeout']}, sw={dropped['sw_error']}, exc={dropped['exception']})",
            f"Avg latency: {avg_latency:.1f} ms",
            f"CSV: {csv_path.name}",
            f"TXT: {txt_path.name}",
        ]
        if total < self.NUM_SAMPLES:
            lines.append(f"Aborted after {idx} attempts; insufficient valid signatures.")

        console_text = "\n".join(lines)
        try:
            txt_path.parent.mkdir(parents=True, exist_ok=True)
            with txt_path.open("w") as f:
                f.write(console_text + "\n")
                f.flush()
                os.fsync(f.fileno())
            try:
                dir_fd = os.open(str(txt_path.parent), os.O_RDONLY)
                os.fsync(dir_fd)
                os.close(dir_fd)
            except Exception:
                pass
        except Exception as e:
            logger.warning("Failed to write text log: %s", e)
        screen_text = f"Status: {final_status.upper()}\nDetails saved to microSD"

        logger.info("Bias test results:\n%s", console_text)
        print(console_text)

        self.run_screen(
            LargeIconStatusScreen,
            title="Bias Test",
            status_headline=None,
            text=screen_text,
            show_back_button=False,
        )
        return Destination(MainMenuView)

