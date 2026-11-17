from eval import resources


def sample(cpu_s, monotonic, rss_mb=100.0):
    return {"cpu_s": cpu_s, "monotonic": monotonic, "rss_mb": rss_mb}


def test_cpu_percentage_is_relative_to_one_core():
    result = resources.summarise([sample(0.0, 0.0), sample(1.0, 2.0)])
    assert result["status"] == "ok"
    assert result["cpu_pct"] == 50.0
    assert result["interval_s"] == 2.0


def test_rss_reports_the_peak_not_the_last_sample():
    result = resources.summarise([sample(0.0, 0.0, 100.0), sample(0.5, 1.0, 260.0),
                                  sample(1.0, 2.0, 180.0)])
    assert result["rss_mb_peak"] == 260.0


def test_one_sample_is_not_a_measurement():
    result = resources.summarise([sample(0.0, 0.0)])
    assert result["status"] == "insufficient_samples"
    assert result["cpu_pct"] is None
    assert result["rss_mb"] is None


def test_zero_elapsed_time_is_rejected():
    result = resources.summarise([sample(0.0, 5.0), sample(0.2, 5.0)])
    assert result["status"] == "insufficient_samples"
    assert result["cpu_pct"] is None


def test_sampler_reports_unavailable_when_proc_is_missing(monkeypatch):
    monkeypatch.setattr(resources, "supported", lambda: False)
    sampler = resources.Sampler(pid=1)
    sampler.start()
    result = sampler.stop()
    assert result["status"] == "proc_unavailable"
    assert result["cpu_pct"] is None
