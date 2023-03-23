from modules.compliance.compliance_base import Compliance


class ComplianceMany(Compliance):
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
                enabled = self.is_enabled(sheet, name, entry)
                self.update_result(sheet, name, entry_dict["level"], enabled, entry_dict["source"])
