from modules.compliance.compliance_base import Compliance
from utils.loader import load_configuration


class GenerateOne(Compliance):
    def __init__(self):
        super().__init__()
        self._configuration_rules = load_configuration("configuration_rules", "configs/compliance/")

    def _worker(self, sheets_to_check):
        if not self._output_file:
            raise ValueError("No file path provided")
        string_to_add = ""
        columns = ["name", "level", "condition", "guidelineName"]
        name_index = columns.index("name")
        level_index = columns.index("level")
        conf_mapping = self._database_instance.configuration_mapping
        for field in conf_mapping:
            tmp_string = field + " "
            sheet = conf_mapping[field]
            query_filter = ""
            if isinstance(sheet, dict):
                table_to_search = list(sheet.keys())[0]
                name_to_search = sheet[table_to_search]
                query_filter = "WHERE name == \"" + name_to_search + "\""
                sheet = table_to_search
            columns = self.sheet_columns.get(sheet, columns)
            guideline = list(sheets_to_check[sheet].keys())[0]
            table_name = self._database_instance.get_table_name(sheet, guideline, sheets_to_check[sheet][guideline])
            self._database_instance.input([table_name], other_filter=query_filter)
            data = self._database_instance.output(columns)
            field_rules = self._configuration_rules.get(field, {})
            allow_string = field_rules.get("enable", "name")
            deny_string = field_rules.get("disable", "-name")
            separator = field_rules.get("separator", " ")
            # This parameter is needed to avoid having separators even if nothing gets added to deny (like ciphersuites)
            added_negatives = field_rules.get("added_negatives", False)
            replacements = field_rules.get("replacements", [])
            for entry in data:
                added = True
                name = entry[name_index]
                for replacement in replacements:
                    name = name.replace(replacement, replacements[replacement])
                if entry[level_index] in ["must", "recommended"]:
                    tmp_string += allow_string.replace("name", name)
                elif entry[level_index] in ["must not", "not recommended"]:
                    tmp_string += deny_string.replace("name", name)
                    added = added_negatives
                else:
                    added = False
                if added:
                    tmp_string += separator

            if tmp_string and tmp_string[-1] == ":":
                tmp_string = tmp_string[:-1]
            if len(tmp_string) != len(field) + 1:
                string_to_add += "\n" + tmp_string
        with open("configs/compliance/template_apache.conf", "r") as f:
            base_conf = f.read()
        with open(self._output_file, "w") as f:
            f.write(base_conf + "\n" + string_to_add)
        self._output_dict["Done"] = True




