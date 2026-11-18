"""Bounded asynchronous microbatches; model work stays off the ASGI event loop."""

import asyncio


class ScoringQueue:
    def __init__(self, scorer, *, batch_size, wait_ms, capacity):
        self.scorer = scorer
        self.batch_size = batch_size
        self.wait_s = wait_ms/1000
        self.queue = asyncio.Queue(maxsize=capacity)
        self.worker = None
        self.closing = False

    async def score(self, features):
        if self.closing:
            raise RuntimeError("scoring queue is closing")
        if self.worker is None:
            self.worker = asyncio.create_task(self._work())
        future = asyncio.get_running_loop().create_future()
        await self.queue.put((features, future))
        return await future

    async def _work(self):
        while True:
            first = await self.queue.get()
            if first is None:
                self.queue.task_done()
                return
            batch, stop = [first], False
            deadline = asyncio.get_running_loop().time()+self.wait_s
            while len(batch) < self.batch_size:
                try:
                    item = self.queue.get_nowait()
                except asyncio.QueueEmpty:
                    remaining = deadline-asyncio.get_running_loop().time()
                    if remaining <= 0:
                        break
                    try:
                        item = await asyncio.wait_for(self.queue.get(), remaining)
                    except asyncio.TimeoutError:
                        break
                if item is None:
                    self.queue.task_done()
                    stop = True
                    break
                batch.append(item)
            active = [(row, future) for row, future in batch if not future.cancelled()]
            try:
                if active:
                    scores = await asyncio.to_thread(self.scorer.score_many, [row for row, _ in active])
                    if len(scores) != len(active):
                        raise ValueError("model returned the wrong score count")
                    for (_, future), score in zip(active, scores):
                        if not future.done():
                            future.set_result(float(score))
            except Exception as exc:
                for _, future in active:
                    if not future.done():
                        future.set_exception(exc)
            finally:
                for _ in batch:
                    self.queue.task_done()
            if stop:
                return

    async def close(self):
        if self.closing:
            if self.worker is not None:
                await self.worker
            return
        self.closing = True
        if self.worker is not None:
            await self.queue.put(None)
            await self.worker
