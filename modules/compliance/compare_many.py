from modules.compliance.compliance_base import Compliance
from utils.globals import DEFAULT_COLUMNS


class CompareMany(Compliance):
    def _worker(self, sheets_to_check, hostname):
        """
        :param sheets_to_check: dict of sheets that should be checked in the form: sheet:{protocol: version_of_protocol}
        :type sheets_to_check: dict

        :return: processed results
        :rtype: dict
        """
        if not self._user_configuration:
            raise ValueError("No configuration provided")
        columns = DEFAULT_COLUMNS
        # fill the entries field with the data from the sheets
        entries = self._retrieve_entries(sheets_to_check, columns)
        evaluated_entries = self._evaluate_entries(sheets_to_check, columns, entries)
        for sheet in evaluated_entries:
            for entry_dict in evaluated_entries[sheet].values():
                original_sheet = sheet
                entry = entry_dict["entry"]
                columns = DEFAULT_COLUMNS
                # If the sheet isn't in the dictionary then I can use the default value
                columns = self.sheet_columns.get(sheet, {"columns": columns})["columns"]
                name_index = columns.index("name")
                name_columns = self.sheet_columns.get(sheet, {}).get("name_columns", [name_index])
                # if it has multiple name_columns they get only shown in the output
                name = "_".join([str(entry[i]) for i in name_columns])
                level = entry_dict["level"]
                enabled = entry_dict["enabled"]
                valid_condition = entry_dict["valid_condition"]
                note = entry_dict["note"]
                # Filter for TLS1.3 ciphers
                if name in self.tls1_3_ciphers:
                    sheet = "CipherSuitesTLS1.3"
                self.update_result(sheet, name, level, enabled, entry_dict["source"], valid_condition, hostname)
                if note and self._output_dict[sheet].get(name) is not None:
                    self._output_dict[sheet][name]["notes"] = entry_dict.get("note")
                if sheet == "KeyLengths" and enabled and valid_condition and level in ["recommended", "must"]:
                    self.valid_keysize = True
                sheet = original_sheet
