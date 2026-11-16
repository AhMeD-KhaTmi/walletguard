import importlib.util
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "make_creds", ROOT / "locust" / "data" / "make_creds.py")
make_creds = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(make_creds)


def test_generation_is_deterministic_for_a_seed():
    first = make_creds.generate(seed=42, count=200, valid_fraction=0.1)
    second = make_creds.generate(seed=42, count=200, valid_fraction=0.1)
    assert first == second
    assert make_creds.generate(seed=43, count=200, valid_fraction=0.1) != first


def test_valid_fraction_is_known_by_construction():
    dataset = make_creds.generate(seed=1, count=100, valid_fraction=0.25)
    valid = [entry for entry in dataset["entries"] if entry["kind"] == "valid"]
    assert len(valid) == 25
    assert dataset["valid_count"] == len(valid)


def test_valid_entries_are_demo_accounts_and_invalid_are_synthetic():
    dataset = make_creds.generate(seed=7, count=50, valid_fraction=1.0)
    demo = dict(make_creds.demo_accounts())
    for entry in dataset["entries"]:
        assert entry["username"] in demo
        assert entry["password"] == demo[entry["username"]]
    dataset = make_creds.generate(seed=7, count=50, valid_fraction=0.0)
    for entry in dataset["entries"]:
        assert entry["kind"] == "invalid"
        assert entry["username"].startswith("u_")
        assert entry["username"] not in demo


def test_identifiers_are_unique_and_ordered():
    dataset = make_creds.generate(seed=3, count=40, valid_fraction=0.5)
    ids = [entry["id"] for entry in dataset["entries"]]
    assert len(ids) == len(set(ids)) == 40
    assert ids == [f"c{index:05d}" for index in range(1, 41)]


def test_written_file_reproduces_from_its_recorded_seed(tmp_path):
    dataset = make_creds.generate(seed=11, count=60, valid_fraction=0.2)
    path = tmp_path / "creds.json"
    make_creds.write(dataset, path)
    reread = json.loads(path.read_text())
    assert reread == dataset
    assert make_creds.file_hash(path) == make_creds.file_hash(path)


def test_rejects_impossible_parameters():
    for kwargs in ({"count": 0}, {"valid_fraction": 1.5}, {"valid_fraction": -0.1}):
        try:
            make_creds.generate(**kwargs)
        except ValueError:
            continue
        raise AssertionError(f"accepted invalid parameters {kwargs}")
