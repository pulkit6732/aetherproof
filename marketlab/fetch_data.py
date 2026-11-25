"""Download the SPY price series MarketLab compares against (Yahoo public chart endpoint).
The data is not stored in the repository. Run: python marketlab/fetch_data.py"""
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
FILES = {"spy_yahoo.json": "range=10y&interval=1d", "spy_1m.json": "range=7d&interval=1m"}


def main():
    os.makedirs(os.path.join(HERE, "data"), exist_ok=True)
    for name, q in FILES.items():
        url = f"https://query1.finance.yahoo.com/v8/finance/chart/SPY?{q}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=30) as r, open(os.path.join(HERE, "data", name), "wb") as f:
                f.write(r.read())
            print(f"saved data/{name}")
        except OSError as e:
            print(f"could not fetch {name}: {e}; run_tests.py will skip the real data comparison", file=sys.stderr)


if __name__ == "__main__":
    main()
