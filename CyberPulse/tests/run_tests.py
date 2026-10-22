"""
Comprehensive Test Runner for CyberPulse Threat Intelligence Engine.
Executes all unit tests and outputs clean test status.
"""
import unittest
import sys
import os

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from tests.test_detector import TestIOCDetector
from tests.test_scorer import TestRiskScorer
from tests.test_modules import TestTelemetryModules
from tests.test_report import TestReportAndHistory
from tests.test_api import TestCyberPulseAPI
from tests.test_rules import TestDefensiveRuleGen
from tests.test_graph import TestThreatGraphGen
from tests.test_decay import TestDecayAndAccuracyEngine
from tests.test_stix import TestSTIX21Gen
from tests.test_webhook import TestWebhookDispatcher
from tests.test_attacks import TestAttackAnalyzer
from tests.test_web_security import TestWebSecurity
from tests.test_velocity import TestAttackVelocity
from tests.test_pipeline_story import TestThreatPipelineAndStory
from tests.test_internal_assets import TestInternalAndLoopbackAssets


def run_all_tests():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestIOCDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestRiskScorer))
    suite.addTests(loader.loadTestsFromTestCase(TestTelemetryModules))
    suite.addTests(loader.loadTestsFromTestCase(TestReportAndHistory))
    suite.addTests(loader.loadTestsFromTestCase(TestCyberPulseAPI))
    suite.addTests(loader.loadTestsFromTestCase(TestDefensiveRuleGen))
    suite.addTests(loader.loadTestsFromTestCase(TestThreatGraphGen))
    suite.addTests(loader.loadTestsFromTestCase(TestDecayAndAccuracyEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestSTIX21Gen))
    suite.addTests(loader.loadTestsFromTestCase(TestWebhookDispatcher))
    suite.addTests(loader.loadTestsFromTestCase(TestAttackAnalyzer))
    suite.addTests(loader.loadTestsFromTestCase(TestWebSecurity))
    suite.addTests(loader.loadTestsFromTestCase(TestAttackVelocity))
    suite.addTests(loader.loadTestsFromTestCase(TestThreatPipelineAndStory))
    suite.addTests(loader.loadTestsFromTestCase(TestInternalAndLoopbackAssets))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 60)
    print(f"Total Tests Run: {result.testsRun}")
    print(f"Errors: {len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print("=" * 60)

    if result.wasSuccessful():
        print(">> ALL TESTS PASSED SUCCESSFULLY! <<")
        return 0
    else:
        print(">> SOME TESTS FAILED! <<")
        return 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
