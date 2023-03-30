from modules.compliance.compliance_base import Compliance


class ComplianceOne(Compliance):
    def _worker(self, sheets_to_check):
        """
        :param sheets_to_check: dict of sheets that should be checked in the form: sheet:{protocol, version_of_protocol}
        :type sheets_to_check: dict

        :return: processed results
        :rtype: dict
        """
        if not self._user_configuration:
            raise ValueError("No configuration provided")
        columns = ["name", "level", "condition", "guidelineName"]
        for sheet in sheets_to_check:
            # If the sheet isn't in the dictionary then I can use the default value
            columns = self.sheet_columns.get(sheet, columns)
            name_index = columns.index("name")
            level_index = columns.index("level")
            condition_index = columns.index("condition")
            guideline = list(sheets_to_check[sheet].keys())[0]
            if not self._output_dict.get(sheet):
                self._output_dict[sheet] = {}
            table_name = self._database_instance.get_table_name(sheet, guideline, sheets_to_check[sheet][guideline])
            self._database_instance.input([table_name])
            data = self._database_instance.output(columns)
            config_field = sheet
            for entry in data:
                if config_field:
                    name = entry[name_index]
                    level = entry[level_index]
                    enabled = self._condition_parser.is_enabled(self._user_configuration, config_field, name, entry)
                    valid_condition = True
                    condition = entry[condition_index]
                    if condition:
                        valid_condition = self._condition_parser.run(condition, enabled)
                        if self._condition_parser.entry_updates.get("levels"):
                            levels = self._condition_parser.entry_updates.get("levels")
                            levels.insert(0, level)
                            to_use = self.level_to_use(levels)
                            level = levels[to_use]
                    has_alternative = self._condition_parser.entry_updates.get("has_alternative")
                    if has_alternative:
                        # This is to trigger the output condition. This works because I'm assuming that "THIS" is only
                        # used in a positive (recommended, must) context.
                        valid_condition = True
                    self.update_result(sheet, name, level, enabled, entry[-1], valid_condition)

                    if has_alternative and self._output_dict[sheet].get(name) and \
                            isinstance(condition, str) and condition.count(" ") > 1:
                        parts = entry[condition_index].split(" ")
                        # Tokens[1] is the logical operator
                        note = f"\nNOTE: {name} {parts[1].upper()} {' '.join(parts[2:])} is needed"
                        self._output_dict[sheet][name] += note
