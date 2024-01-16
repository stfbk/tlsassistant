import sqlite3
from copy import deepcopy
from typing import Tuple

import pandas as pd

from utils.configs import sheets_mapping, different_names_pos, sheet_columns, guidelines, converters, has_merged_names
from utils.filler_utils import get_requirements_columns, get_columns_count_for_guideline, split_sheet, \
    get_version_name_for_database, get_guideline_name_for_database, is_double_guideline, get_first_col_for_guideline, \
    get_column

dataframe = pd.read_excel("guidelines.xlsx", header=[0, 1], sheet_name=list(sheets_mapping.keys()),
                          converters=converters, dtype=str)

sheet_with_extra_table = {
    "TLS extensions": ("applies to version", "TlsVersionExtension")
}

conn = sqlite3.connect("requirements.db")
cur = conn.cursor()


def prepare_database():
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    for table in cur.fetchall():
        cur.execute("DELETE FROM " + table[0])
    conn.commit()


def insert_guideline_info():
    cur.executemany("INSERT OR REPLACE INTO Guideline VALUES (?, ?)",
                    [(guideline, guidelines[guideline]) for guideline in guidelines])


def get_cell_for_df(df: pd.DataFrame, row_index: int, header):
    col_index = 0
    for col_index, col in enumerate(df.columns):
        if col[0] == header[0]:
            break
    return df.iloc[row_index: row_index + 1, col_index:col_index + 1].iat[0, 0]


def get_name_from_index_for_sheet(index, sheet_name: str) -> str:
    """
    Gets the name of the item for that row. Some sheets have the name column in a different position, for that case
    see the different_names_pos dictionary
    :param index: row index
    :param sheet_name: sheet in which the search should be done
    :return: item_name: the name for the row at index in the sheet
    """
    column = different_names_pos.get(sheet_name, (0, 1))[0]
    return dataframe[sheet_name].iloc[index:index + 1, column:column + 1].iat[0, 0]


def get_additional_info(index, sheet_name: str):
    column, lengths = different_names_pos.get(sheet_name, (0, 1))
    return_vals = []
    tmp_df = dataframe[sheet_name].iloc[index:index + 1, column:column + lengths]
    if lengths > 1:
        for i in range(1, lengths):
            val = tmp_df.iat[0, i]
            return_vals.append(val)
    return return_vals


def already_parsed(col_name: str) -> bool:
    for _, c2 in sheet_with_extra_table.items():
        if c2[0] == col_name.strip():
            return True
    return False


def values_to_add(r: pd.Series, columns: pd.Index) -> Tuple:
    """Given a series of values checks if those values belong to columns that were already parsed
    :param r The row (Series) containing the values that need to be checked
    :param columns: The columns of the dataframe from which the row is taken
    """
    val_list = r.to_list()
    i = 0
    for c in columns:
        if already_parsed(c[0]):
            val_list.pop(i)
        else:
            i += 1
    return tuple(val_list)


def has_extra_table(sheet_name: str) -> Tuple:
    return sheet_with_extra_table.get(sheet_name, ())


def fill_extra_table(sheet_name: str) -> bool:
    """
    This function takes the name of a sheet as a param, uses it to get the column names from which it should get data
    and the table in which to insert the data using the sheet_with_extra_table dictionary and then adds this data to the
    database.

    :param sheet_name: the sheet that has an extra table
    :return: False if the sheet doesn't have an extra table, True if it committed to the database
    """
    column, table = sheet_with_extra_table.get(sheet_name, (None, None))
    if not column or not table:
        return False
    file_sheet: pd.DataFrame = dataframe[sheet_name]
    # The first column is almost always the names column
    names: pd.Series = get_column(file_sheet, 0)
    # Get only the columns that must be inserted in the extra table
    versions = file_sheet.filter(like=column)
    versions_names = {}
    insertion_query = f"INSERT OR REPLACE INTO {table} VALUES (?, ?)"
    values_to_insert = []
    #   prepare the mapping from index to column
    for pos, version in enumerate(versions.columns.to_list()):
        versions_names[pos] = version[1]

    for pos, content in versions.iterrows():
        name = names[pos]
        # This variable i is used to cycle through the column's name without having to add it to the dataframe
        # It can probably be avoided by using the join in pandas, but I can't get it to work
        i = 0
        for c in content:
            if pd.notna(c):
                values_to_insert.append(
                    (versions_names[i % len(versions.columns)], name))
            i += 1
    cur.executemany(insertion_query, values_to_insert)
    conn.commit()
    return True


if __name__ == "__main__":
    prepare_database()
    insert_guideline_info()
    guidelines_mapping = {}
    for guideline in guidelines:
        guidelines_mapping[guideline.upper()] = guideline
    for sheet in dataframe:
        sheet_mapped = sheets_mapping.get(sheet.strip())
        if isinstance(sheet, str) and sheet_mapped:
            done = False
            values = []
            if has_extra_table(sheet):
                fill_extra_table(sheet)
            general_dataframe, guidelines_dataframe = split_sheet(dataframe[sheet])
            values_tuple = ()
            # old_values is needed for some strange cases like key_signature
            old_values = []
            for row in general_dataframe.iterrows():
                # row[0] is the index, row[1] is the actual content of the line
                values_tuple = values_to_add(row[1], general_dataframe.columns)
                if not len(old_values):
                    old_values = [v for v in values_tuple]
                else:
                    tmp_list = []
                    for i, v in enumerate(values_tuple):
                        if pd.isna(v) and v != old_values[i]:
                            tmp_list.append(old_values[i])
                        else:
                            tmp_list.append(v)
                    values_tuple = tuple(tmp_list)
                    old_values = tmp_list
                if values_tuple[0] != "Certificate Type":
                    values.append(values_tuple)
            values_string = "("
            values_string += "?," * len(values_tuple)
            # Remove last ',' and replace it with ')'
            values_string = values_string[:-1] + ")"
            sql_query = f"INSERT OR REPLACE INTO {sheet_mapped} VALUES " + values_string
            cur.executemany(sql_query, values)
            conn.commit()
            values = []

            # Start of guideline specific part
            requirements_columns = get_requirements_columns(guidelines_dataframe, sheet)
            guidelines_columns_count = get_columns_count_for_guideline(guidelines_dataframe)

            values_dict = {}
            last_item = ""

            # maybe this whole part can be rewritten using iloc
            old_name = ""
            for row in guidelines_dataframe.iterrows():
                row_dictionary = row[1].to_dict()
                for header in row_dictionary:
                    # header[0] is guideline_name
                    item_name = get_name_from_index_for_sheet(row[0], sheet)
                    if pd.isna(item_name) and sheet in has_merged_names:
                        item_name = old_name
                    else:
                        old_name = item_name
                    guideline = get_guideline_name_for_database(header[0])
                    version_name = get_version_name_for_database(header[1])
                    table_name = sheet_mapped + guideline + version_name
                    content = row_dictionary[header]
                    if header[1] in requirements_columns[header[0]]:
                        # This is the case for sheets like cipher suite
                        if sheet_columns.get(sheet, {}).get(header[0]):
                            level_column = get_first_col_for_guideline(guidelines_dataframe, guideline)
                            level = get_cell_for_df(guidelines_dataframe, row[0], (guideline, level_column))
                            # If the cell is empty and the level isn’t negative (must not, not recommended)
                            # then "must not" is used as the level.
                            if pd.notna(content) or level in ["not recommended", "must not"]:
                                if content not in ["recommended", "must"]:
                                    content = level
                            else:
                                content = "must not"

                        # this block is to prepare the dictionary
                        if not values_dict.get(table_name):
                            values_dict[table_name] = {row[0]: []}
                        if not values_dict[table_name].get(row[0]):
                            values_dict[table_name][row[0]] = []
                        # end of the block

                        # Vertically merged cells contain the value only in the first cell
                        if pd.isna(item_name) and not pd.isna(content):
                            item_name = values_dict[table_name][row[0] - 1][0]

                        # First the guideline name is added
                        values_dict[table_name][row[0]].append(guidelines_mapping.get(guideline, guideline))

                        # Then the name of the row is added
                        values_dict[table_name][row[0]].append(item_name)
                        # If this table needs extra data it gets added here
                        for el in get_additional_info(row[0], sheet):
                            values_dict[table_name][row[0]].append(el)

                        values_dict[table_name][row[0]].append(content)

                    elif pd.notna(header[1]) and \
                            get_first_col_for_guideline(guidelines_dataframe, header[0]) != header[1]:
                        # update all the lists of the same guideline with the condition
                        columns_to_apply = []
                        if " [" in header[1]:
                            columns_to_apply = header[1].split(" [")[1].replace("]", "").split(",")
                            columns_to_apply = [int(c.strip()) for c in columns_to_apply]
                        counter = 0
                        for t_name in values_dict:
                            guideline_db_name = get_guideline_name_for_database(header[0])
                            # this is needed only for the case of KeyLengthsBSI and KeyLengths BSI (from ...)
                            has_valid_underscore = "_" in guideline_db_name and "_" in t_name
                            if t_name.startswith(sheet_mapped + guideline_db_name):
                                if "_" not in t_name or has_valid_underscore:
                                    counter += 1
                                    if " [" in header[1] and counter not in columns_to_apply:
                                        continue
                                    values_dict[t_name][row[0]].append(content)
                    if is_double_guideline(header[0]):
                        tokens = header[0].split("+")
                        base_guideline = tokens[0].replace("(", "").strip()
                        for other_guideline in tokens[1:]:
                            other_name = get_guideline_name_for_database(other_guideline)
                            other_table = sheet_mapped + other_name + version_name
                            values_dict[other_table] = deepcopy(values_dict[table_name])
                            for el in values_dict[other_table]:
                                # Update the guideline name
                                for i, entry in enumerate(values_dict[other_table][el]):
                                    if isinstance(entry, str) and entry.upper() == base_guideline.upper():
                                        values_dict[other_table][el][i] = other_name

            # Convert all the data into tuples to add them to the database and group them by guideline name
            values_groups = {}
            for table in values_dict:
                # Get the number of columns for the actual table
                table_columns_count = len(cur.execute(f"PRAGMA table_info({table})").fetchall())
                entries = values_dict[table]

                # # This is to prevent the "this or X" condition to appear in tables that don't need it
                # # this condition checks if the guideline has multiple versions for this sheet
                # if table.startswith("Protocol") and table[len("Protocol"):] not in [g.upper() for g in guidelines]:
                #     for entry in entries:
                #         entry = entries[entry]
                #         # Since the problem is a condition, and it only verifies if there are four elements.
                #         # Last element is the condition
                #         # Second to last is the level
                #         print(entry)
                #         if len(entry) > 3 and pd.notna(entry[-1]):
                #             if entry[-2][-1] != "°":
                #                 entry[-1] = None
                last_level = None

                # This is to prevent the "this or X" condition to appear in tables that don't need it, only works
                # for the case of Protocol sheet and only if the conditions are in adjacent lines
                if table.startswith("Protocol"):
                    for index, entry in entries.items():
                        # skip first element
                        if index == 0:
                            continue
                        if len(entry) > 3 and pd.notna(entry[-1]) and pd.notna(entries[index - 1][-1]):
                            if entry[-2] != entries[index - 1][-2]:
                                entry[-1] = None
                                entries[index - 1][-1] = None

                if not values_groups.get(table):
                    values_groups[table] = []
                for index in entries:
                    entry = entries[index]
                    if pd.notna(entry[1]) and entry[1] != "Certificate Type" and entry[1] != "NIST":
                        # The double check is needed because of the case Mozilla + AGID which share the same pointer to
                        # the list of values
                        if len(entry) < table_columns_count:
                            entry.insert(0, index)
                        # Every remaining column is filled with None
                        while len(entry) < table_columns_count:
                            entry.append(None)
                        values_groups[table].append(tuple(entry))
            for table in values_groups:
                values = values_groups[table]
                values_string = "("
                # The values list should contain tuples that are all the same size
                values_string += "?," * (len(values[0]))
                # Remove last ',' and replace it with ')'
                values_string = values_string[:-1] + ")"
                sql_query = f"INSERT OR REPLACE INTO {table} VALUES " + values_string
                cur.executemany(sql_query, values)
                conn.commit()
