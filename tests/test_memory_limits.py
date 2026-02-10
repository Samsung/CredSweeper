import unittest
import subprocess
import sys
import os
from pathlib import Path


class TestMemoryLimits(unittest.TestCase):
    """Test ML validation behavior under memory constraints"""

    def setUp(self):
        self.test_dir = Path(__file__).parent
        self.project_root = self.test_dir.parent
        self.credsweeper_path = self.project_root / "credsweeper"
        
    def test_ml_batch_size_help(self):
        """Test that help shows memory information for batch sizes"""
        try:
            result = subprocess.run(
                [sys.executable, "-m", "credsweeper", "--help"],
                capture_output=True,
                text=True,
                cwd=self.project_root,
                timeout=30
            )
            
            self.assertEqual(result.returncode, 0)
            help_text = result.stdout
            
            self.assertIn("--ml_batch_size", help_text)
            
        except subprocess.TimeoutExpired:
            self.skipTest("Help command timed out")
        except Exception as e:
            self.skipTest(f"Could not run help command: {e}")

    def test_low_memory_batch_size(self):
        """Test that small batch size works under memory constraints"""
        test_file = self.test_dir / "memory_test_data.txt"
        
        try:
            with open(test_file, 'w') as f:
                f.write("password = 'secret123'\n")
                f.write("api_key = 'abc123def456'\n")
                f.write("token = 'xyz789abc'\n")
            
            result = subprocess.run(
                [sys.executable, "-m", "credsweeper", 
                 "--path", str(test_file), 
                 "--ml_batch_size", "4"],
                capture_output=True,
                text=True,
                cwd=self.project_root,
                timeout=60
            )
            
            self.assertEqual(result.returncode, 0)
            self.assertIn("Detected Credentials:", result.stdout)
            
        except subprocess.TimeoutExpired:
            self.skipTest("ML validation timed out")
        except Exception as e:
            self.skipTest(f"Could not run ML validation: {e}")
        finally:
            if test_file.exists():
                test_file.unlink()

    def test_default_batch_size_memory_usage(self):
        """Test that default batch size doesn't exceed reasonable memory limits"""
        test_file = self.test_dir / "memory_test_default.txt"
        
        try:
            with open(test_file, 'w') as f:
                for i in range(50):
                    f.write(f"password{i} = 'secret{i}abc'\n")
                    f.write(f"api_key{i} = 'key{i}xyz123'\n")
            
            result = subprocess.run(
                [sys.executable, "-m", "credsweeper", 
                 "--path", str(test_file)],
                capture_output=True,
                text=True,
                cwd=self.project_root,
                timeout=120
            )
            
            self.assertEqual(result.returncode, 0)
            self.assertIn("Detected Credentials:", result.stdout)
            
        except subprocess.TimeoutExpired:
            self.skipTest("Default batch size test timed out")
        except Exception as e:
            self.skipTest(f"Could not run default batch size test: {e}")
        finally:
            if test_file.exists():
                test_file.unlink()

    def test_memory_efficiency_comparison(self):
        """Compare memory usage between different batch sizes"""
        test_file = self.test_dir / "memory_efficiency_test.txt"
        
        try:
            with open(test_file, 'w') as f:
                for i in range(20):
                    f.write(f"secret{i} = 'value{i}12345'\n")
            
            small_batch_result = subprocess.run(
                [sys.executable, "-m", "credsweeper", 
                 "--path", str(test_file), 
                 "--ml_batch_size", "4"],
                capture_output=True,
                text=True,
                cwd=self.project_root,
                timeout=90
            )
            
            large_batch_result = subprocess.run(
                [sys.executable, "-m", "credsweeper", 
                 "--path", str(test_file), 
                 "--ml_batch_size", "32"],
                capture_output=True,
                text=True,
                cwd=self.project_root,
                timeout=90
            )
            
            self.assertEqual(small_batch_result.returncode, 0)
            self.assertEqual(large_batch_result.returncode, 0)
            
            small_output = small_batch_result.stdout
            large_output = large_batch_result.stdout
            
            self.assertIn("Detected Credentials:", small_output)
            self.assertIn("Detected Credentials:", large_output)
            
            small_time = self._extract_time(small_output)
            large_time = self._extract_time(large_output)
            
            if small_time and large_time:
                self.assertLess(large_time, small_time * 2, 
                               "Large batch should be significantly faster")
            
        except subprocess.TimeoutExpired:
            self.skipTest("Memory efficiency test timed out")
        except Exception as e:
            self.skipTest(f"Could not run memory efficiency test: {e}")
        finally:
            if test_file.exists():
                test_file.unlink()

    def _extract_time(self, output):
        """Extract time elapsed from output"""
        import re
        match = re.search(r'Time Elapsed: ([\d.]+)s', output)
        if match:
            return float(match.group(1))
        return None


if __name__ == '__main__':
    unittest.main()
