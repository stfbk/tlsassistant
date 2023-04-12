from typing import Dict, List

import pandas as pd

from .configs import guidelines, levels_mapping, sheet_columns


def split_sheet(sheet: pd.DataFrame):
    """
    Splits the sheet at the first guideline column to have two dataframes one with general data and the other with the
    data of the guidelines.
    :param sheet: the sheet that needs to be split
    :return: the two dataframes
    """
    guideline_column_index = get_first_guideline_column_pos(sheet)
    # This split is done to make things more organised
    general_dataframe: pd.DataFrame = sheet.iloc[:, :guideline_column_index]
    protocols_dataframe: pd.DataFrame = sheet.iloc[:, guideline_column_index:]
    return general_dataframe, protocols_dataframe


def get_requirements_columns(requirements_df: pd.DataFrame, sheet_name: str) -> Dict[str, List[str]]:
    """Returns a dictionary containing Guideline_name as key and a list composed of columns that contain evaluations"""
    # Get the first row (after the header) of the dataframe and convert it to a dict for easier access
    row_dict = requirements_df.iloc[0:1, :].to_dict()
    result_dict = {}
    # col is the header so col[0] is the guideline_name and col[1] is the actual column name
    for col in row_dict:
        also_add = []
        if " " in col[0]:
            parts = col[0].split(" ")
            if "+" in parts[1]:
                for el in parts[1].split("+")[1:]:
                    also_add.append(el.strip(")"))
        if not result_dict.get(col[0]):
            result_dict[col[0]] = []
        val = row_dict[col]
        if val[0] in levels_mapping.values():
            result_dict[col[0]].append(col[1])
            for val in also_add:
                if not result_dict.get(val):
                    result_dict[val] = []
                result_dict[val].append(col[1])
    for guideline in result_dict:
        valid_indexes = sheet_columns.get(sheet_name, {}).get(guideline)
        if valid_indexes:
            result_dict[guideline] = get_column_names_from_indexes(requirements_df, guideline, valid_indexes)
    return result_dict


def get_columns_count_for_guideline(df: pd.DataFrame) -> Dict:
    """The header may have the same value at index 0 (the guideline) with different values at index 1. So it is useful to
    know how many columns each guideline uses.
    :param df Pandas dataframe. Specifically the guideline specific one.
    """
    results = {}
    values_count_dict = df.columns.value_counts()
    for col in values_count_dict.keys():
        if results.get(col[0]):
            results[col[0]] += values_count_dict[col]
        else:
            results[col[0]] = values_count_dict[col]
    return results


def get_first_guideline_column_pos(s: pd.DataFrame):
    """Searches the first column in the dataframe that contains guideline specific data and returns its index.
    :param s: The dataframe in which the column should be searched
    """
    for i, c in enumerate(s.columns):
        first_row = c[0]
        c_name = first_row.split(" ")[0] if " " in first_row else first_row
        if c_name.lower() in [g.lower() for g in guidelines]:
            return i
    # Maybe should raise an exception
    return -1


def get_column_names_from_indexes(requirements_df: pd.DataFrame, guideline_name: str, valid_indexes: List[int]) -> \
        List[str]:
    """
    This function returns the names of the columns from its indexes.
    At the moment it is only used to get the column names for the sheets that have requirements columns that don't
    contain guideline values such as "Cipher Suites"
    :param requirements_df: The dataframe in which the research should be done
    :param guideline_name: The name of the guideline to search
    :param valid_indexes: The indexes to search the name for
    :return:
    """
    row_dict = requirements_df.iloc[0:1, :].to_dict()
    columns = []
    i = 0
    for col in row_dict:
        if col[0] == guideline_name:
            if i in valid_indexes:
                columns.append(col[1])
            i += 1
    return columns


def get_version_name_for_database(version_name: str):
    """This function prepares the version_name to be usable in the database as art of a table's name"""
    version_name = version_name if "Unnamed" not in version_name else ""
    version_name = version_name.strip().title().replace(" ", "").replace("-", "").replace("/", "_").replace("#", "") \
        .strip(".")
    return version_name.upper()


def get_guideline_name_for_database(guideline: str):
    """This function prepares the guideline_name to be usable in the database as part of a table's name"""
    if " " in guideline:
        tokens = guideline.split(" ")
        if "+" in tokens[1]:
            # The "added" entries are already present in the dict
            guideline = tokens[0]
        elif len(tokens) > 2 and "/" in tokens[-1]:
            guideline = tokens[0] + tokens[-1].replace("/", "_")
    return guideline.strip(")").upper()


def is_double_guideline(guideline: str):
    return " " in guideline and guideline.split(" ")[1][1] == "+"


def get_first_col_for_guideline(df: pd.DataFrame, guideline: str):
    for col in df.columns:
        if col[0] == guideline:
            return col[1]


def get_column(df: pd.DataFrame, index: int):
    return df.iloc[:, index]
