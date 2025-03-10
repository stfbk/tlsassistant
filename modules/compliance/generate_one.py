from modules.compliance.compliance_base import Generator
from utils.globals import DEFAULT_COLUMNS
from configs import different_names_pos


class GenerateOne(Generator):
    def _worker(self, sheets_to_check, hostname):
        if not self._config_class.output_file():
            raise ValueError("No output file path provided")
        columns = DEFAULT_COLUMNS
        conf_mapping = self._configuration_mapping
        for field in conf_mapping:
            if not self._output_dict.get(field):
                self._output_dict[field] = {}
            sheet, query_filter = self.get_sheet_filter(conf_mapping[field])
            columns_temp = self.sheet_columns.get(sheet, columns)
            if isinstance(columns_temp, dict):
                columns_temp = columns_temp["columns"]
            # Only the first guideline of each sheet is the interesting one
            if sheets_to_check[sheet]:
                guideline = list(sheets_to_check[sheet].keys())[0]
                table_name = self._database_instance.get_table_name(
                    sheet, guideline, sheets_to_check[sheet][guideline])
                data = self._database_instance.run(
                    [table_name], other_filter=query_filter, columns=columns_temp)
                if self._reverse_mapping.get(sheet) in different_names_pos:
                    _, num_columns = different_names_pos[self._reverse_mapping.get(
                        sheet)]
                    new_data = []
                    for el in data:
                        new_name = ""
                        for i in range(num_columns):
                            new_name += str(el[i]) + "_"
                        new_el = tuple([new_name[:-1]])+el[num_columns:]
                        new_data.append(new_el)
                    for _ in range(num_columns-1):
                        columns_temp.pop(1)
                    data = new_data
                if data:
                    field_rules = self._configuration_rules.get(field, {})
                    self._config_class.add_configuration_for_field(
                        field, field_rules, data, columns_temp, table_name)
