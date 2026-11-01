
import unittest
from unittest.mock import patch

from pypi_client import PyPIClient


class TestPyPIExtras(unittest.TestCase):

    def setUp(self):
        # 실제 PyPI 응답 형식과 유사한 가짜 메타데이터
        requires_dist = [
            "urllib3>=1.26",
            "PySocks>=1.7; extra == 'socks'",
            "rich>=13.0; extra == 'cli'",
            "colorama>=0.4; sys_platform == 'win32'",
            "packaging>=23.0; python_version >= '3.8'",
        ]

        self.metadata = {
            "info": {"requires_dist": requires_dist},
            "requires_dist": requires_dist,
        }

        # 메타데이터 조회를 Mock으로 대체하므로
        # 네트워크 관련 초기화는 필요하지 않음
        self.client = PyPIClient.__new__(PyPIClient)

        self.patcher = patch.object(
            PyPIClient,
            "get_release_metadata",
            return_value=self.metadata,
        )
        self.mock_metadata = self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def names(self, extras=None):
        dependencies = self.client.get_dependencies(
            "demo-package",
            "1.0.0",
            extras=extras,
        )
        return {dep.name.lower() for dep in dependencies}

    def test_01_no_extras(self):
        """선택하지 않은 extras 의존성이 포함되지 않아야 한다."""
        names = self.names()

        self.assertIn("urllib3", names)
        self.assertNotIn("pysocks", names)
        self.assertNotIn("rich", names)

    def test_02_socks_extra(self):
        """socks를 선택하면 추가 의존성이 포함되어야 한다."""
        names = self.names({"socks"})

        self.assertIn("urllib3", names)
        self.assertIn("pysocks", names)
        self.assertNotIn("rich", names)

    def test_03_cli_extra(self):
        """cli를 선택하면 해당 extra 의존성만 포함한다."""
        names = self.names({"cli"})

        self.assertIn("urllib3", names)
        self.assertIn("rich", names)
        self.assertNotIn("pysocks", names)

    def test_04_multiple_extras(self):
        """여러 extras를 함께 선택할 수 있어야 한다."""
        names = self.names({"socks", "cli"})

        self.assertIn("urllib3", names)
        self.assertIn("pysocks", names)
        self.assertIn("rich", names)

    def test_05_unknown_extra(self):
        """존재하지 않는 extra는 추가 의존성을 발생시키지 않는다."""
        names = self.names({"unknown"})

        self.assertIn("urllib3", names)
        self.assertNotIn("pysocks", names)
        self.assertNotIn("rich", names)

    def test_06_environment_marker(self):
        """Python 버전 조건을 평가해야 한다."""
        names = self.names()

        self.assertIn("packaging", names)

    def test_07_platform_marker(self):
        """Windows에서만 colorama가 포함되어야 한다."""
        names = self.names()

        if __import__("sys").platform == "win32":
            self.assertIn("colorama", names)
        else:
            self.assertNotIn("colorama", names)

    def test_08_metadata_mock_called(self):
        """외부 요청 대신 Mock 메타데이터가 사용되는지 확인한다."""
        self.names({"socks"})

        self.mock_metadata.assert_called()


if __name__ == "__main__":
    unittest.main()
