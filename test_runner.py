#!/usr/bin/env python3
"""
Automated Test Runner & Security Audit Validator
Runs all test suites (Security, Auth, Rate Limiting, SQL Injection)
and generates an executive test execution report.
"""
import sys
import unittest
import time

def run_all_tests():
    print("=" * 70)
    print("        SECURE LOGIN SYSTEM - AUTOMATED SECURITY TEST SUITE       ")
    print("=" * 70)
    print("Target Environment: Python 3.12+ / FastAPI / SQLite / OWASP Standards\n")

    loader = unittest.TestLoader()
    suite = loader.discover("tests", pattern="test_*.py")

    start_time = time.time()
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    elapsed = time.time() - start_time

    print("\n" + "=" * 70)
    print(f"Total Tests Run   : {result.testsRun}")
    print(f"Passed            : {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures          : {len(result.failures)}")
    print(f"Errors            : {len(result.errors)}")
    print(f"Execution Time    : {elapsed:.2f} seconds")
    
    if result.wasSuccessful():
        print("\n [ALL SECURITY & FUNCTIONAL TESTS PASSED SUCCESSFULLY!]")
        print("=" * 70)
        return 0
    else:
        print("\n [TEST SUITE ENCOUNTERED FAILURES / ERRORS]")
        print("=" * 70)
        return 1

if __name__ == "__main__":
    sys.exit(run_all_tests())
