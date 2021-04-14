import argparse
from argparse import RawTextHelpFormatter
from tlsa.tlsa import Tlsa

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="TLSA Help",
        formatter_class=RawTextHelpFormatter,  # todo: change the desc
    )
    args = parser.parse_args()
    tlsa = Tlsa(args)
