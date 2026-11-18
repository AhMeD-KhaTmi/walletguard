import asyncio
import threading

import pytest

from waf.scoring_queue import ScoringQueue


class RecordingScorer:
    def __init__(self):
        self.batches = []

    def score_many(self, rows):
        assert threading.current_thread() is not threading.main_thread()
        self.batches.append(len(rows))
        return [r["value"] for r in rows]


async def test_concurrent_scoring_keeps_results_and_batches_off_thread():
    scorer = RecordingScorer()
    queue = ScoringQueue(scorer, batch_size=8, wait_ms=2, capacity=4)
    results = await asyncio.gather(*(queue.score({"value": i}) for i in range(20)))
    assert results == list(range(20))
    assert sum(scorer.batches) == 20 and max(scorer.batches) <= 8
    assert len(scorer.batches) < 20
    await queue.close()
    await queue.close()
    assert queue.worker.done() and queue.queue.empty()
    with pytest.raises(RuntimeError, match="closing"):
        await queue.score({"value": 1})


async def test_canceled_call_does_not_lose_later_results():
    queue = ScoringQueue(RecordingScorer(), batch_size=8, wait_ms=2, capacity=2)
    canceled = asyncio.create_task(queue.score({"value": 1}))
    await asyncio.sleep(0)
    canceled.cancel()
    with pytest.raises(asyncio.CancelledError):
        await canceled
    assert await queue.score({"value": 2}) == 2
    await queue.close()
    await queue.queue.join()


@pytest.mark.parametrize("wrong_count", [False, True])
async def test_model_errors_reach_every_waiter_and_shutdown_drains(wrong_count):
    class Broken:
        def score_many(self, rows):
            if wrong_count:
                return []
            raise ValueError("model failure")

    queue = ScoringQueue(Broken(), batch_size=8, wait_ms=2, capacity=8)
    replies = await asyncio.gather(*(queue.score({"value": i}) for i in range(4)), return_exceptions=True)
    assert all(isinstance(r, ValueError) for r in replies)
    await queue.close()
    await queue.queue.join()


async def test_single_row_mode_has_no_batch_wait():
    scorer = RecordingScorer()
    queue = ScoringQueue(scorer, batch_size=1, wait_ms=100, capacity=8)
    assert await queue.score({"value": 3}) == 3
    assert scorer.batches == [1]
    await queue.close()
