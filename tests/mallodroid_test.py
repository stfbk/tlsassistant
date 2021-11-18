# move this file to the root folder to make it work.
from modules.android.wrappers.mallodroid import Mallodroid
import logging

# logging.basicConfig(level=logging.DEBUG)
md = Mallodroid()
print(md.run(path="test.apk"))
