from modules.compliance.compliance_base import Compliance


class CompareMany(Compliance):
    def _worker(self, sheets_to_check):
        """
        :param sheets_to_check: dict of sheets that should be checked in the form: sheet:{protocol: version_of_protocol}
        :type sheets_to_check: dict

        :return: processed results
        :rtype: dict
        """
        if not self._user_configuration:
            raise ValueError("No configuration provided")
        columns = ["name", "level", "condition", "guidelineName"]
        name_index = columns.index("name")
        # fill the entries field with the data from the sheets
        self._retrieve_entries(sheets_to_check, columns)
        self._evaluate_entries(sheets_to_check, columns)
        for sheet in self.evaluated_entries:
            for entry_dict in self.evaluated_entries[sheet].values():
                entry = entry_dict["entry"]
                name = entry[name_index]
                level = entry_dict["level"]
                enabled = entry_dict["enabled"]
                valid_condition = entry_dict["valid_condition"]
                note = entry_dict["note"]

                self.update_result(sheet, name, level, enabled, entry_dict["source"], valid_condition)
                if note and self._output_dict[sheet].get(name) is not None:
                    self._output_dict[sheet][name] += entry_dict.get("note")
