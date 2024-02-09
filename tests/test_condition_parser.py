from modules.compliance.wrappers.conditionparser import ConditionParser
from modules.compliance.compliance_base import Compliance
import json
with open("tests/tests_data/testssl_dump.json") as f:
    data = json.load(f)
compliance = Compliance()
compliance.prepare_testssl_output(data)
condition_parser = ConditionParser(compliance._user_configuration)
def test_logic():
    assert condition_parser.run("True and False", False) == False
    assert condition_parser.run("True and True", False) == True
    assert condition_parser.run("True or False", False) == True
    # parenthesis
    assert condition_parser.run("(True and False) or True", False) == True
    assert condition_parser.run("(True and False) or False", False) == False
    # nested parenthesis
    assert condition_parser.run("(True and (False or True))", False) == True
    assert condition_parser.run("(True and (False or False))", False) == False
    # double nested parenthesis
    assert condition_parser.run("(True and (False or (True and False)))", False) == False
    # split nested parenthesis
    assert condition_parser.run("(True and (False or True)) and (True and (False or True))", False) == True
    # test xor
    assert condition_parser.run("True xor False", False) == True
    assert condition_parser.run("True xor True", False) == False

def test_this():
    condition = "THIS or PROTOCOLS TLS 1.3"
    assert condition_parser.run(condition, False) == True
    condition = "THIS or PROTOCOLS TLS 1.1"
    assert condition_parser.run(condition, False) == False


