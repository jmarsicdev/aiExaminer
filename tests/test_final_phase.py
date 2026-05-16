import unittest
import os
from src.utils.crypto import calculate_hashes
from src.ai.anomaly.detector import LogAnomalyDetector
from src.db.manager import DatabaseManager

class TestFinalPhase(unittest.TestCase):

    def test_crypto_hashing(self):
        data = b"hello forensic world"
        hashes = calculate_hashes(data)
        self.assertEqual(hashes['md5'], "9bc23cf39f60a7435beb1dfc540c1c22")
        self.assertTrue(len(hashes['sha256']) == 64)

    def test_log_anomaly_detector(self):
        detector = LogAnomalyDetector()
        # Create some dummy log data
        normal_logs = "INFO: User logged in\n" * 20
        anomalous_logs = normal_logs + "CRITICAL: ERROR AT 0x999999999999999999999999999999999999999\n"
        
        result = detector.analyze_logs(anomalous_logs)
        self.assertIn("AI LOG ANOMALY ANALYSIS", result)
        self.assertIn("Anomalies (ML):", result)

    def test_database_manager(self):
        db_path = "test_case.db"
        if os.path.exists(db_path):
            os.remove(db_path)
            
        manager = DatabaseManager(db_path)
        case_id = manager.create_case("CASE-001", "John Doe", "Test Case")
        self.assertEqual(case_id, 1)
        
        evidence_id = manager.add_evidence(case_id, "/path/to/image.img")
        self.assertEqual(evidence_id, 1)
        
        manager.add_artifact(evidence_id, "/file/path.txt", "md5hash", "sha256hash", "NLP", "Positive sentiment")
        
        cases = manager.get_all_cases()
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0].case_number, "CASE-001")
        
        if os.path.exists(db_path):
            os.remove(db_path)

if __name__ == '__main__':
    unittest.main()
