import os
import re
import subprocess
from typing import TextIO, Dict

import pandas as pd

from utils.configs import sheets_mapping, additional_keys, different_templates, RANDOM_STRING, GUIDELINE_BLOCKS, \
    TEMPLATE_FILE
from utils.filler_utils import split_sheet, get_requirements_columns, get_version_name_for_database, \
    get_guideline_name_for_database

# IMPORTANT NOTE "sheet" means the original file name, "sheet_name" is the mapped one

# This dict is filled during the initialization
additional_templates = {}


# End of configurations

def get_block(f: TextIO):
    text = ""
    last_line = "a"
    while last_line != "}" + os.linesep and last_line != "":
        last_line = f.readline()
        text += last_line
    return text


def get_template_for(sheet: str, template: str):
    template = additional_templates.get(sheet, template)
    original_key_ref = ""
    lines = template.splitlines()
    for index, line in enumerate(lines):
        if "@relation" in line:
            original_key_ref = template.splitlines()[index]
    for var_name in additional_keys.get(sheet, []):
        new_key_ref = original_key_ref.replace("[name", f"[name, {var_name},")
        new_key_ref = new_key_ref.replace(",]", "]")
        template = template.replace(original_key_ref, new_key_ref)

    return template.replace("Sheet", sheet)


def generate_template(df: Dict[str, pd.DataFrame]):
    file = open(TEMPLATE_FILE, "r")
    general_part = ""
    for _ in range(GUIDELINE_BLOCKS):
        general_part += get_block(file)
    # this part is only needed to make the template compliant to prisma guideline.
    # this two regexes are only needed because the number of spaces/tabs between type and name is variable.
    general_part = re.sub(rf"Sheet{RANDOM_STRING} *Sheet{RANDOM_STRING}\[]", "", general_part)
    for sheet in different_templates:
        general_part = re.sub(rf"{sheet}{RANDOM_STRING} *{sheet}{RANDOM_STRING}\[]", "", general_part)
    general_part += "\n// Guidelines tables"
    with open("output.prisma", "w") as f:
        f.write(general_part)
    # Remove the "Sheet" part that is useless
    get_block(file)
    # Get the general template
    general_template = get_block(file)
    for table in different_templates:
        additional_templates[table] = get_block(file)
    for sheet in dataframe:
        # sheet_name is the name that will be used in the database
        sheet_name = sheets_mapping.get(sheet)
        if not sheet_name:
            continue
        actual_template = get_template_for(sheet_name, general_template)
        _, protocols_dataframe = split_sheet(df[sheet])
        requirements_columns = get_requirements_columns(protocols_dataframe, sheet)
        # prepare the guidelines for the next step
        for guideline in requirements_columns:
            for column_name in requirements_columns[guideline]:
                version_name = get_version_name_for_database(column_name)
                guideline = get_guideline_name_for_database(guideline)
                new_name = (guideline + version_name).upper()
                with open("output.prisma", "a") as f:
                    f.write(actual_template.replace("7WJsEz", new_name))
    subprocess.call(["prisma", "format", "--schema=output.prisma"])
    subprocess.call(["prisma", "db", "push", "--schema=output.prisma"])


if __name__ == "__main__":
    dataframe = pd.read_excel("./guidelines.xlsx", header=[0, 1], sheet_name=list(sheets_mapping.keys()))
    generate_template(dataframe)
