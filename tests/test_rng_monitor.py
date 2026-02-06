from seedsigner.hardware.rng_monitor import HardwareRngHealthMonitor


def test_rng_monitor_rejects_low_entropy_sample():
    monitor = HardwareRngHealthMonitor()
    assert monitor.add_sample(bytes([0] * 32)) is False
    assert monitor.is_healthy() is False
    assert monitor.failure_reason() is not None


def test_rng_monitor_rejects_looping_samples_over_hundred_window():
    monitor = HardwareRngHealthMonitor()
    sample_a = bytes(range(32))
    sample_b = bytes(range(31, -1, -1))

    for i in range(99):
        sample = sample_a if i % 2 == 0 else sample_b
        assert monitor.add_sample(sample)

    assert monitor.add_sample(sample_b) is False
    assert monitor.is_healthy() is False


def test_rng_monitor_accepts_distinct_high_entropy_samples():
    monitor = HardwareRngHealthMonitor()
    for i in range(100):
        sample = bytes(((j + i * 17) % 256) for j in range(32))
        assert monitor.add_sample(sample)

    assert monitor.is_healthy() is True
    assert monitor.failure_reason() is None


def test_rng_monitor_rejects_hundred_identical_samples():
    monitor = HardwareRngHealthMonitor()
    sample = bytes(range(32))
    for _ in range(99):
        assert monitor.add_sample(sample)
    assert monitor.add_sample(sample) is False
    assert monitor.is_healthy() is False
