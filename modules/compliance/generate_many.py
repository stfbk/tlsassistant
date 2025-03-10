from modules.compliance.compliance_base import Generator
from utils.globals import DEFAULT_COLUMNS
from configs import different_names_pos


class GenerateMany(Generator):
    def _worker(self, sheets_to_check, hostname):
        if not self._config_class.output_file():
            raise ValueError("No output file path provided")
        columns = DEFAULT_COLUMNS
        conf_mapping = self._configuration_mapping
        for field in conf_mapping:
            if not self._output_dict.get(field):
                self._output_dict[field] = {}
            tables = {}
            sheet, query_filter = self.get_sheet_filter(conf_mapping[field])
            query_filters = {sheet: query_filter}
            sheets_to_use = {sheet: sheets_to_check[sheet]}
            # Retrieve entries from the database
            entries = self._retrieve_entries(sheets_to_use, columns, query_filters, tables)
            evaluated_entries = self._evaluate_entries(sheets_to_use, columns, entries)
            field_rules = self._configuration_rules.get(field, {})
            # the guideline here is defined as None because it will be defined in the function
            columns_temp = self.sheet_columns.get(sheet, columns)
            if isinstance(columns_temp, dict):
                columns_temp = columns_temp["columns"]
            if self._reverse_mapping.get(sheet) in different_names_pos:
                _, num_columns = different_names_pos[self._reverse_mapping.get(sheet)]
                for entry in evaluated_entries[sheet].values():
                    el = entry["entry"]
                    new_name = ""
                    for i in range(num_columns):
                        new_name += str(el[i]) + "_"
                    new_el = tuple([new_name[:-1]])+el[num_columns:]
                    entry["entry"] = new_el
                for _ in range(num_columns-1):
                    columns_temp.pop(1)
            # get guidelines from sheets_to_check
            guidelines = tables[sheet]
            self._config_class.add_configuration_for_field(field, field_rules, evaluated_entries[sheet].values(),
                                                           columns_temp, ",".join(guidelines))
        for field in self._config_class.conditions_to_check:
            condition = self._config_class.conditions_to_check[field]



