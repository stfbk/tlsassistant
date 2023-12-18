import sys
import os
# move to root directory
if os.getcwd().endswith("tests"):
    os.chdir("..")
# add root directory to path to make imports work
sys.path.append(os.getcwd())