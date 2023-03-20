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
        level_index = columns.index("level")
        entries = {}
        tables = []
        for sheet in sheets_to_check:
            for guideline in sheets_to_check[sheet]:
                if not self._output_dict.get(sheet):
                    self._output_dict[sheet] = {}
                table_name = self._database_instance.get_table_name(sheet, guideline, sheets_to_check[sheet][guideline])
                tables.append(table_name)
            self._database_instance.input(tables, other_filter="ORDER BY name")
            data = self._database_instance.output(columns)
            entries[sheet] = data
            tables = []
        self.entries = entries
        # A more fitting name could be current_requirement_level
        resulting_level = "<Not mentioned>"
        for sheet in sheets_to_check:
            counter = 1
            source_guideline = entries[sheet][-1]
            for entry in entries[sheet]:
                name = entry[name_index]
                entry_level = entry[level_index]
                guideline = entry[-1]
                if entry_level != resulting_level:
                    levels = [resulting_level, entry_level]
                    best_level = self.evaluation_to_use(levels)
                    # if best_level is 0 the source_guideline is the same
                    if best_level:
                        source_guideline = guideline
                    resulting_level = levels[best_level]
                # The entries are ordered by name so every time the counter is the same as the number of guidelines to
                # check it is time to add the entry to the output dictionary.
                if sheet and counter == len(sheets_to_check[sheet]):
                    counter = 0
                    enabled = self.is_enabled(sheet, name, entry)
                    self.update_result(sheet, name, resulting_level, enabled, source_guideline)
                    # the resulting level is reset so that it doesn't influence the next element.
                    resulting_level = "<Not mentioned>"
                counter += 1
