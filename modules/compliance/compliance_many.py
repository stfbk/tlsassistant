from modules.compliance.compliance_base import Compliance


# TODO fix this
class ComplianceMany(Compliance):
    def _worker(self, sheets_to_check):
        """
        :param sheets_to_check: dict of sheets that should be checked in the form: sheet:{protocol, version_of_protocol}
        :type sheets_to_check: dict

        :return: processed results
        :rtype: dict
        """
        if not self._user_configuration:
            raise ValueError("No configuration provided")
        columns = ["name", "evaluation", "condition"]
        name_index = columns.index("name")
        evaluation_index = columns.index("evaluation")
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
        actual_evaluation = "<Not mentioned>"
        for sheet in sheets_to_check:
            config_field = self._database_instance.sheet_mapping.get(sheet)
            counter = 0
            for entry in entries[sheet]:
                name = entry[name_index]
                evaluation = entry[evaluation_index]
                if evaluation != actual_evaluation:
                    evaluations = [actual_evaluation, evaluation]
                    best_evaluation = self.evaluation_to_use(evaluations)
                    actual_evaluation = evaluations[best_evaluation]
                if config_field and counter % len(sheets_to_check[sheet]) == 0:
                    field_value = self._user_configuration[config_field]
                    enabled = False
                    if isinstance(field_value, dict):
                        enabled = field_value.get(name, None)
                        if enabled is None:
                            enabled = True if "all" in field_value else False
                    elif isinstance(field_value, list):
                        enabled = name in field_value
                    self.update_result(sheet, name, actual_evaluation, enabled)
                    actual_evaluation = "<Not mentioned>"
                counter += 1
