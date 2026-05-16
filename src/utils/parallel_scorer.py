"""
Parallel relevance scoring using a thread pool.

Wraps src.ai.relevance_scorer.score_file so many files can be scored
concurrently on a multi-core machine.
"""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable


def score_files_parallel(
    file_jobs: list[dict],
    max_workers: int = 4,
    progress_cb: Callable[[int, int], None] | None = None,
) -> list[tuple[str, object]]:
    """
    Score a batch of files in parallel.

    Each job dict must have keys matching score_file() parameters:
        file_path, file_category, entropy, entities,
        content_sample, is_deleted, mtime

    Returns list of (file_path, ScoreResult) in completion order.
    progress_cb(done, total) is called after each file finishes.
    """
    from src.ai.relevance_scorer import score_file

    results = []
    total   = len(file_jobs)
    done    = 0

    def _score(job: dict):
        return job["file_path"], score_file(
            file_path     = job["file_path"],
            file_category = job.get("file_category", "unknown"),
            entropy       = job.get("entropy", 0.0),
            entities      = job.get("entities", []),
            content_sample= job.get("content_sample", b""),
            is_deleted    = job.get("is_deleted", False),
            mtime         = job.get("mtime"),
        )

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_score, job): job for job in file_jobs}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                job = futures[future]
                results.append((job["file_path"], None))
            done += 1
            if progress_cb:
                progress_cb(done, total)

    return results
