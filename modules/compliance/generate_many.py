from modules.compliance.compliance_base import Generator


class GenerateMany(Generator):
    def _worker(self, sheets_to_check, hostname):
        if not self._config_class.output_file():
            raise ValueError("No output file path provided")
        columns = ["name", "level", "condition", "guidelineName"]
        conf_mapping = self._configuration_mapping
        # fill the entries field with the data from the sheets
        self._retrieve_entries(sheets_to_check, columns)
        self._evaluate_entries(sheets_to_check, columns)
        for field in conf_mapping:
            if not self._output_dict.get(field):
                self._output_dict[field] = {}
            sheet = conf_mapping[field]
            target = None
            # Dictionaries are used for specific things like a directive that enables an extension for this reason it is
            # used a filter on the query to get that specific thing by name
            if isinstance(sheet, dict):
                table_to_search = list(sheet.keys())[0]
                # Since for generate_many the data are retrieved and processed before this block the filtering is
                # postponed by using the target variable
                target = sheet[table_to_search]
                sheet = table_to_search
            field_rules = self._configuration_rules.get(field, {})
            # the guideline here is defined as None because it will be defined in the function
            self._config_class.add_configuration_for_field(field, field_rules, self.evaluated_entries[sheet].values(),
                                                           columns, None, target)
        for field in self._config_class.conditions_to_check:
            condition = self._config_class.conditions_to_check[field]



