from modules.compliance.compliance_base import Compliance
from utils.globals import DEFAULT_COLUMNS
from configs import has_numeric_id

class CompareOne(Compliance):
    def _worker(self, sheets_to_check, hostname):
        """
        :param sheets_to_check: dict of sheets that should be checked in the form: sheet:{protocol, version_of_protocol}
        :type sheets_to_check: dict

        :return: processed results
        :rtype: dict
        """
        if not self._user_configuration:
            raise ValueError("No configuration provided")
        for sheet in sheets_to_check:
            original_sheet = sheet
            columns_orig = DEFAULT_COLUMNS
            # If the sheet isn't in the dictionary then I can use the default value
            query_filter = self.get_filters(sheet)
            columns = self.sheet_columns.get(sheet, {"columns": columns_orig})["columns"]
            if sheet in has_numeric_id:
                # if the sheet has a numeric id then I need to add it to the columns
                columns = ["id"] + columns
            name_index = columns.index("name")
            name_columns = self.sheet_columns.get(sheet, {}).get("name_columns", [name_index])
            level_index = columns.index("level")
            condition_index = columns.index("condition")
            guideline = list(sheets_to_check[sheet].keys())[0]
            table_name = self._database_instance.get_table_name(sheet, guideline, sheets_to_check[sheet][guideline])
            data = self._database_instance.run(tables=[table_name], columns=columns, other_filter=query_filter)
            config_field = sheet
            for entry in data:
                if config_field:
                    self._evaluate_one_entry(
                        entry, sheet, name_columns, level_index, name_index, condition_index, hostname
                    )