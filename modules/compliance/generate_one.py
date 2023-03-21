import os.path

from modules.compliance.compliance_base import Generator


class GenerateOne(Generator):
    def _worker(self, sheets_to_check):
        if not self._config_output:
            raise ValueError("No output file path provided")
        string_to_add = ""
        columns = ["name", "level", "condition", "guidelineName"]
        name_index = columns.index("name")
        level_index = columns.index("level")
        conf_mapping = self.configuration_mapping
        for field in conf_mapping:
            if not self._output_dict.get(field):
                self._output_dict[field] = {}
            tmp_string = field + " "
            sheet = conf_mapping[field]
            query_filter = ""
            # Dictionaries are used for specific things like a directive that enables an extension for this reason it is
            # used a filter on the query to get that specific thing by name
            if isinstance(sheet, dict):
                table_to_search = list(sheet.keys())[0]
                name_to_search = sheet[table_to_search]
                query_filter = "WHERE name == \"" + name_to_search + "\""
                sheet = table_to_search
            columns = self.sheet_columns.get(sheet, columns)
            # Only the first guideline of each sheet is the interesting one
            guideline = list(sheets_to_check[sheet].keys())[0]
            table_name = self._database_instance.get_table_name(sheet, guideline, sheets_to_check[sheet][guideline])
            self._database_instance.input([table_name], other_filter=query_filter)
            data = self._database_instance.output(columns)
            field_rules = self._configuration_rules.get(field, {})
            # the idea is that it is possible to define a custom value to insert like on/off or name to use the name
            # defined in the config file
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
                    self._output_dict[field][name] = True
                elif entry[level_index] in ["must not", "not recommended"]:
                    tmp_string += deny_string.replace("name", name)
                    added = added_negatives
                    self._output_dict[field][name] = False
                else:
                    added = False
                    self._output_dict[field][name] = False

                if added:
                    tmp_string += separator

            if tmp_string and tmp_string[-1] == ":":
                tmp_string = tmp_string[:-1]
            if len(tmp_string) != len(field) + 1:
                string_to_add += "\n" + tmp_string
        if not os.path.isfile(self._config_template):
            raise FileNotFoundError("Invalid template file")
        with open(self._config_template, "r") as f:
            base_conf = f.read()
        with open(self._config_output, "w") as f:
            f.write(base_conf + "\n" + string_to_add)
