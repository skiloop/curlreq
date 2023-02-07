import unittest


class ClientTests(unittest.TestCase):
    def test_something(self):
        import requests
        requests.request()
        self.assertEqual(True, False)  # add assertion here


if __name__ == '__main__':
    unittest.main()
