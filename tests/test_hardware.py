"""Tests for hardware profiling and the settings it chooses.

Two things are being defended. The first is the decision itself — one worker
on a spinning disk, a smaller rule set on a small machine — because getting
the disk backwards is the difference between a forty-minute scan and a
ninety-minute one.

The second is the *sentence*. Nobody is asked to pick a performance mode, so
the only thing making an automatic choice feel like respect rather than
opacity is that the user is told what was chosen in words they can check
against their own computer.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from sentinel.core.config import Config
from sentinel.system.hardware import (
    MODEST_RAM_BYTES,
    HardwareProfile,
    MachineTier,
    StorageKind,
    Tuning,
    apply_to,
    detect_storage,
    profile_machine,
    recommend,
    stored_summary,
    tune_once,
)

GB = 1024**3

#: The machine the whole project is aimed at.
TARGET = HardwareProfile(
    total_ram_bytes=4 * GB,
    physical_cores=2,
    logical_cores=2,
    storage=StorageKind.ROTATIONAL,
    storage_source="the storage driver",
)

MODERN = HardwareProfile(
    total_ram_bytes=16 * GB,
    physical_cores=8,
    logical_cores=16,
    storage=StorageKind.SOLID_STATE,
    storage_source="the storage driver",
)


# ----------------------------------------------------------------------
# reading the machine
# ----------------------------------------------------------------------

class TestProfiling:
    def test_profiles_this_machine_without_raising(self) -> None:
        profile = profile_machine()
        assert profile.logical_cores >= 1
        assert profile.storage in set(StorageKind)

    def test_detects_this_machine_s_storage(self, tmp_path: Path) -> None:
        kind, source = detect_storage(tmp_path)
        # Either it worked, or it honestly said it did not.
        assert kind in set(StorageKind)
        if kind is StorageKind.UNKNOWN:
            assert source == "not detected"
        else:
            assert source

    def test_unknown_storage_is_treated_as_spinning(self) -> None:
        # Being conservative on an SSD costs some speed. Being wrong the
        # other way makes a hard disk thrash. Only one of those is
        # recoverable by waiting.
        unknown = HardwareProfile(storage=StorageKind.UNKNOWN)
        assert unknown.spins

    def test_solid_state_does_not_spin(self) -> None:
        assert not MODERN.spins


class TestTier:
    def test_the_target_machine_is_modest(self) -> None:
        assert TARGET.tier is MachineTier.MODEST

    def test_a_modern_machine_is_capable(self) -> None:
        assert MODERN.tier is MachineTier.CAPABLE

    def test_low_core_count_is_modest_whatever_the_memory(self) -> None:
        big_but_slow = HardwareProfile(total_ram_bytes=32 * GB, logical_cores=2)
        assert big_but_slow.tier is MachineTier.MODEST

    def test_the_boundary_is_inclusive(self) -> None:
        exactly = HardwareProfile(total_ram_bytes=MODEST_RAM_BYTES, logical_cores=8)
        assert exactly.tier is MachineTier.MODEST


# ----------------------------------------------------------------------
# the decision
# ----------------------------------------------------------------------

class TestRecommendations:
    def test_a_spinning_disk_gets_exactly_one_worker(self) -> None:
        # Parallel reads on a rotating platter make the head seek between
        # them and roughly halve throughput. The core count is irrelevant.
        assert recommend(TARGET).threads == 1

    def test_core_count_does_not_override_a_spinning_disk(self) -> None:
        many_cores_one_disk = HardwareProfile(
            total_ram_bytes=32 * GB, physical_cores=16, logical_cores=32,
            storage=StorageKind.ROTATIONAL,
        )
        assert recommend(many_cores_one_disk).threads == 1

    def test_unknown_storage_also_gets_one_worker(self) -> None:
        unknown = HardwareProfile(total_ram_bytes=16 * GB, logical_cores=8)
        assert recommend(unknown).threads == 1

    def test_solid_state_uses_several_workers(self) -> None:
        assert recommend(MODERN).threads > 1

    def test_worker_count_is_capped(self) -> None:
        # Past a handful the gain flattens while memory keeps climbing.
        huge = HardwareProfile(
            total_ram_bytes=128 * GB, logical_cores=128,
            storage=StorageKind.SOLID_STATE,
        )
        assert recommend(huge).threads <= 8

    def test_a_modest_machine_trims_the_rule_set(self) -> None:
        tuning = recommend(TARGET)
        assert 0 < tuning.yara_file_budget <= 400
        assert tuning.max_file_size < 256 * 1024 * 1024

    def test_a_capable_machine_keeps_every_rule(self) -> None:
        assert recommend(MODERN).yara_file_budget == 0


class TestExplanations:
    """The sentence matters as much as the setting."""

    @pytest.mark.parametrize("profile", [TARGET, MODERN, HardwareProfile()])
    def test_every_choice_is_explained(self, profile: HardwareProfile) -> None:
        tuning = recommend(profile)
        assert len(tuning.reasons) >= 2
        assert tuning.explain().strip()

    @pytest.mark.parametrize("profile", [TARGET, MODERN, HardwareProfile()])
    def test_no_jargon(self, profile: HardwareProfile) -> None:
        text = recommend(profile).explain().lower()
        for word in ("thread", "worker", "yara", "heuristic", "i/o", "buffer",
                     "signature database", "concurrency"):
            assert word not in text, f"{word!r} in {text!r}"

    def test_the_hard_disk_sentence_says_why(self) -> None:
        # From the design rules: this is the sentence that turns a limitation
        # into evidence the software respected their machine.
        text = recommend(TARGET).explain().lower()
        assert "hard disk" in text
        assert "one file at a time" in text
        assert "faster" in text

    def test_admitting_it_could_not_tell(self) -> None:
        text = recommend(HardwareProfile(storage=StorageKind.UNKNOWN)).explain()
        assert "couldn't tell" in text.lower()


# ----------------------------------------------------------------------
# applying it
# ----------------------------------------------------------------------

class TestApply:
    def test_writes_onto_the_config(self, config: Config) -> None:
        apply_to(config, recommend(TARGET))
        assert config.scan.threads == 1
        assert config.detectors.yara_file_budget == 400

    def test_survives_a_config_missing_the_field(self) -> None:
        class Bare:
            pass

        apply_to(Bare(), recommend(TARGET))  # must not raise


class TestTuneOnce:
    def test_measures_and_applies_on_first_run(
        self, config: Config, db: Any
    ) -> None:
        tuning = tune_once(config, db)
        assert isinstance(tuning, Tuning)
        assert config.scan.threads >= 1
        assert stored_summary(db)

    def test_the_choice_survives_a_restart(self, config: Config, db: Any) -> None:
        # Applying to the in-memory object only makes the setting last
        # exactly one run. The next start reloads threads=0 — "decide
        # automatically" — which on a hard disk means many workers thrashing
        # a drive already established to want one.
        from sentinel.core.config import load_config

        tune_once(config, db)
        chosen = config.scan.threads
        assert chosen >= 1

        reloaded = load_config(config.paths.config_file, use_env=False)
        assert reloaded.scan.threads == chosen
        assert (
            reloaded.detectors.yara_file_budget == config.detectors.yara_file_budget
        )

    def test_a_read_only_config_still_tunes_this_run(
        self, config: Config, db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import sentinel.core.config as config_module

        def refuse(*args: Any, **kwargs: Any) -> Any:
            raise OSError("read-only file system")

        monkeypatch.setattr(config_module, "save_config", refuse)
        tuning = tune_once(config, db)
        assert tuning is not None
        assert config.scan.threads >= 1

    def test_does_not_measure_twice(self, config: Config, db: Any) -> None:
        # The seek probe costs a tenth of a second, and a value re-derived
        # every launch can change every launch — so a user who read "checks
        # one file at a time" would later catch the app contradicting itself.
        assert tune_once(config, db) is not None
        assert tune_once(config, db) is None

    def test_force_measures_again(self, config: Config, db: Any) -> None:
        tune_once(config, db)
        assert tune_once(config, db, force=True) is not None

    def test_a_broken_database_does_not_stop_a_scan(self, config: Config) -> None:
        class Exploding:
            def get_setting(self, key: str) -> str | None:
                raise RuntimeError("no database")

            def set_setting(self, key: str, value: str) -> None:
                raise RuntimeError("no database")

        assert tune_once(config, Exploding()) is None

    def test_measurement_failure_leaves_the_defaults(
        self, config: Config, db: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import sentinel.system.hardware as module

        def explode(*args: Any, **kwargs: Any) -> Any:
            raise OSError("cannot read the disk")

        monkeypatch.setattr(module, "profile_machine", explode)
        before = config.scan.threads
        assert tune_once(config, db) is None
        assert config.scan.threads == before


# ----------------------------------------------------------------------
# the rule budget actually bites
# ----------------------------------------------------------------------

class TestRuleBudget:
    def test_budget_limits_compiled_rule_files(
        self, config: Config, tmp_path: Path
    ) -> None:
        pytest.importorskip("yara", reason="yara-python is not installed")
        from sentinel.engine.detectors.yara_detector import YaraDetector

        rules = tmp_path / "rules"
        rules.mkdir()
        for i in range(6):
            (rules / f"r{i}.yar").write_text(
                f'rule r{i} {{ strings: $a = "marker{i}" condition: $a }}\n',
                encoding="utf-8",
            )
        config.detectors.yara_rules_dir = str(rules)

        config.detectors.yara_file_budget = 2
        limited = YaraDetector(config)
        limited.setup()
        assert limited._rule_count == 2

        config.detectors.yara_file_budget = 0
        everything = YaraDetector(config)
        everything.setup()
        assert everything._rule_count >= 6
