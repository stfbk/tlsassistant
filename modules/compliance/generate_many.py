from modules.compliance.compliance_base import Generator
from utils.globals import DEFAULT_COLUMNS
from configs import different_names_pos
from configs import has_numeric_id
from collections import OrderedDict


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
            if sheet not in sheets_to_check:
                continue
            sheets_to_use = {sheet: sheets_to_check[sheet]}
            # Retrieve entries from the database
            entries = self._retrieve_entries(sheets_to_use, columns, query_filters, tables)
            evaluated_entries = self._evaluate_entries(sheets_to_use, columns, entries)
            # evaluated_entries sorted(OrderedDict(evaluated_entries.items(), key=lambda x:  ))
            evaluated_entries[sheet] = OrderedDict(sorted(list(evaluated_entries.values())[0].items(), key=lambda x: x[1]["priority"], reverse=True))
            field_rules = self._configuration_rules.get(field, {})
            # the guideline here is defined as None because it will be defined in the function
            columns_temp = self.sheet_columns.get(sheet, columns)
            if self.has_tls12 is None and sheet == "Protocol":
                for k,v in evaluated_entries["Protocol"].items():
                    if v.get("entry", [0])[0] == "TLS 1.2":
                        self.has_tls12 = v["level"] not in ["not recommended", "must not"]
                if self.has_tls12 is False:
                    self._ciphers1_2_filter = self._ciphers1_2_filter.replace("\")", "\") AND 1 = 2")
            if isinstance(columns_temp, dict):
                columns_temp = columns_temp["columns"]
            if sheet in has_numeric_id:
                # if the sheet has a numeric id then I need to add it to the columns
                columns_temp = ["id"] + columns_temp
            # get guidelines from sheets_to_check
            guidelines = tables[sheet]
            self._config_class.add_configuration_for_field(field, field_rules, evaluated_entries[sheet].values(),
                                                           columns_temp, ",".join(guidelines))
        for field in self._config_class.conditions_to_check:
            condition = self._config_class.conditions_to_check[field]



