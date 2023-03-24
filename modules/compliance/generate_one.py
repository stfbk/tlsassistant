from modules.compliance.compliance_base import Generator


class GenerateOne(Generator):
    def _worker(self, sheets_to_check):
        if not self._config_class.output_file():
            raise ValueError("No output file path provided")
        columns = ["name", "level", "condition", "guidelineName"]
        name_index = columns.index("name")
        level_index = columns.index("level")
        guideline_index = columns.index("guidelineName")
        conf_mapping = self._configuration_mapping
        for field in conf_mapping:
            if not self._output_dict.get(field):
                self._output_dict[field] = {}
            sheet = conf_mapping[field]
            query_filter = ""
            # Dictionaries are used for specific things like a directive that enables an extension for this reason it is
            # used a filter on the query to get that specific thing by name
            if isinstance(sheet, dict):
                table_to_search = list(sheet.keys())[0]
                name_to_search = sheet[table_to_search]
                query_filter = "WHERE name LIKE \"" + name_to_search + "\""
                sheet = table_to_search
            columns = self.sheet_columns.get(sheet, columns)
            # Only the first guideline of each sheet is the interesting one
            guideline = list(sheets_to_check[sheet].keys())[0]
            table_name = self._database_instance.get_table_name(sheet, guideline, sheets_to_check[sheet][guideline])
            # Get the guideline name saved in the database for this field
            guideline = guideline_index
            self._database_instance.input([table_name], other_filter=query_filter)
            data = self._database_instance.output(columns)
            field_rules = self._configuration_rules.get(field, {})
            self._config_class.add_configuration_for_field(field, field_rules, data, name_index, level_index, guideline)

