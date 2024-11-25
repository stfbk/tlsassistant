import sqlite3

import utils.database as db_utils
from utils.loader import load_configuration
from utils.logger import Logger

# Configs from the tls-compliance-dataset repository
from configs import sheets_mapping


class Database:
    database_file = "dependencies/requirements.db"

    def __init__(self, file: str = database_file):
        self.database_file = file
        self.connection = sqlite3.connect(self.database_file)
        self.cursor = self.connection.cursor()
        self.sheet_mapping = sheets_mapping

        # Retrieve the list of tables from the database
        self.cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")
        self.table_names = [table[0] for table in self.cursor.fetchall()]
        self.__input_dict = {}
        self._logging = Logger("Database wrapper")

    def get_table_name(self, sheet, standard_name, version=""):
        """
        Given the sheet, standard_name and version returns the corresponding database table
        :param: standard_name -- Standard whose data are needed
        :type standard_name: str
        :param: sheet -- Sheet whose data are needed
        :type sheet: str
        :param: version -- (Optional) Standard's version
        :type version: str
        :return: the name of the table
        :rtype: str
        """
        sheet_name = self.get_sheet_name(sheet, sheet)
        standard_name = db_utils.get_standard_name_for_database(standard_name)
        version_name = db_utils.get_version_name_for_database(version)
        return sheet_name + standard_name + version_name

    def get_sheet_name(self, sheet, default_value=None):
        """
        Returns the sheet_name for the sheet, returns None if there isn't a mapping available
        """
        return self.sheet_mapping.get(sheet, default_value)

    def input(self, tables, join_condition="1==1", other_filter="", raw=None):
        """
        Set the input parameters

        :param: tables -- List of tables from which data should be retrieved
        :type tables: list
        :param join_condition: Default to 1==1, the condition to apply to the join in case of multiple tables
        :type join_condition: str
        :param: other_filter -- (Optional) A filter to add to the query the WHERE/AND part will be handled automatically
        :type other_filter: str
        :param: raw -- (Optional) A raw query to execute, if defined the other parameters will be ignored
        :type raw: str
        """
        self.__input_dict = {
            "tables": tables,
            "other_filter": other_filter,
            "join_condition": join_condition,
            "raw": raw
        }

    def output(self, columns="*"):
        """
        Retrieve data from the database.

        :param: tables -- List of tables from which data should be retrieved
        :type columns: list
        """
        raw = self.__input_dict.get("raw")
        if raw:
            self._logging.debug(raw)
            self.cursor.execute(raw)
            return self.cursor.fetchall()

        query = f"SELECT {', '.join(columns)} FROM "
        first = 2
        other_filter = self.__input_dict.get("other_filter")
        for table in self.__input_dict.get("tables", []):
            if first:
                first -= 1
            else:
                query += " JOIN "
            query += table
            if not first:
                join_condition = self.__input_dict["join_condition"]
                if "{table}" in join_condition:
                    join_condition = join_condition.format(table=table)
                query += " " + join_condition
            else:
                first -= 1
        if other_filter:
            query += " " + other_filter
        self._logging.debug(query)
        self.cursor.execute(query)
        return self.cursor.fetchall()

    def run(self, tables, join_condition="1==1", other_filter="", columns="*", raw=None):
        """
        Retrieve data from the database

        :param: tables -- List of tables from which data should be retrieved
        :type tables: list
        :param join_condition: Default to 1==1, the condition to apply to the join in case of multiple tables
        :type join_condition: str
        :param: other_filter -- (Optional) A filter to add to the query the WHERE/AND part will be handled automatically
        :type other_filter: str
        :param: tables -- List of tables from which data should be retrieved
        :type columns: list
        :param: raw -- (Optional) A raw query to execute, if defined the other parameters will be ignored
        :type raw: str
        """
        self.input(tables, join_condition, other_filter, raw)
        return self.output(columns)
