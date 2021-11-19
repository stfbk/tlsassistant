from modules.android.wrappers.super import Super
import logging

# logging.basicConfig(level=logging.DEBUG)
s = Super()
from pprint import pprint

pprint(s.run(path="testdue.apk"))
input("should return cached results")
pprint(s.run(path="testdue.apk"))
