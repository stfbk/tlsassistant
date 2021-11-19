from modules.parse_input_conf import Parser

# p = Parser(to_parse="test_configuration.json").output()
p = Parser(to_parse="include_configuration.json").output()

print(p)
input("parsed! press any key to analyzed the results")
for name, module_args in p.items():
    Module, args = module_args
    module = Module()
    print(module.run(**args))
    input(f"This was {name}, press any key to load next module")
