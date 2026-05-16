"""
Tests for src.utils.parallel_scorer.score_files_parallel
"""
import unittest

from src.utils.parallel_scorer import score_files_parallel
from src.ai.relevance_scorer import ScoreResult


def _make_job(path: str = "/tmp/file.txt") -> dict:
    return {
        "file_path": path,
        "file_category": "text",
        "entropy": 3.5,
        "entities": [],
        "content_sample": b"hello world",
        "is_deleted": False,
        "mtime": None,
    }


class TestScoreFilesParallel(unittest.TestCase):

    # 1. Always returns a list
    def test_returns_list(self):
        result = score_files_parallel([_make_job()])
        self.assertIsInstance(result, list)

    # 2. Empty input returns empty list
    def test_empty_input_returns_empty(self):
        result = score_files_parallel([])
        self.assertEqual(result, [])

    # 3. Five jobs produce five results
    def test_all_jobs_scored(self):
        jobs = [_make_job(f"/tmp/file_{i}.txt") for i in range(5)]
        result = score_files_parallel(jobs)
        self.assertEqual(len(result), 5)

    # 4. Each result is a (path, ScoreResult) tuple
    def test_each_result_has_path_and_score(self):
        jobs = [_make_job("/tmp/check.txt")]
        result = score_files_parallel(jobs)
        path, score = result[0]
        self.assertEqual(path, "/tmp/check.txt")
        self.assertIsInstance(score, ScoreResult)

    # 5. Progress callback is called once per job
    def test_progress_callback_fires(self):
        calls = []
        jobs = [_make_job(f"/tmp/f{i}.txt") for i in range(4)]
        score_files_parallel(jobs, progress_cb=lambda done, total: calls.append((done, total)))
        self.assertEqual(len(calls), 4)

    # 6. The total argument in the callback matches the job count
    def test_progress_total_correct(self):
        totals = []
        jobs = [_make_job(f"/tmp/g{i}.txt") for i in range(3)]
        score_files_parallel(jobs, progress_cb=lambda done, total: totals.append(total))
        self.assertTrue(all(t == 3 for t in totals))

    # 7. max_workers=1 works without error
    def test_max_workers_respected(self):
        jobs = [_make_job(f"/tmp/w{i}.txt") for i in range(3)]
        result = score_files_parallel(jobs, max_workers=1)
        self.assertEqual(len(result), 3)

    # 8. Job with missing required key (file_path) → result has None score, no exception raised
    def test_bad_job_no_crash(self):
        # A job dict that is completely empty triggers a KeyError inside _score,
        # which is caught and converted to (file_path, None).
        # We must supply file_path so the error handler can record it;
        # omit file_category to trigger the KeyError in score_file via missing
        # required positional — actually score_file uses .get() with defaults,
        # so force a TypeError by passing a bad entropy type.
        bad_job = {
            "file_path": "/tmp/bad_job.txt",
            "file_category": "text",
            "entropy": "not_a_number",   # will cause TypeError inside scorer
            "entities": [],
            "content_sample": b"",
        }
        result = score_files_parallel([bad_job])
        self.assertEqual(len(result), 1)
        path, score = result[0]
        self.assertEqual(path, "/tmp/bad_job.txt")
        self.assertIsNone(score)


if __name__ == "__main__":
    unittest.main()
