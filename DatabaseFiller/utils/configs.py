# schema creator configs
TEMPLATE_FILE = "schema_generator/template.prisma"
GUIDELINE_BLOCKS = 15
RANDOM_STRING = "7WJsEz"

# If the sheet has vertically merged cells in the name column add it here
has_merged_names = ["Key lengths"]

# list of sheet_names that need a different template, order is important
different_templates = ["KeyLengths", "CertificateExtensions"]

# The syntax for this is: Sheet: list of keys
# it is assumed that a field with the same name of the key was added using the additional_fields dict
additional_keys = {
}

guidelines = {
    "NIST": "",
    "ANSSI": "",
    "AgID": "",
    "BSI": "",
    "Mozilla": ""
}

levels_mapping = {
    "1": "must",
    "2": "must not",
    "3": "recommended",
    "4": "not recommended",
    "5": "optional",
    "6": "<Not mentioned>"
}

sheets_mapping = {
    "Protocols": "Protocol",
    "Cipher Suites": "CipherSuite",
    "TLS extensions": "Extension",
    "Supported groups": "Groups",
    "Signature algorithms": "Signature",
    "Hash Algorithm": "Hash",
    "Certificate Signature": "CertificateSignature",
    "Key lengths": "KeyLengths",
    "Certificate": "Certificate",
    "Certificate Extensions": "CertificateExtensions",
    "Misc": "Misc"
}

# give both pos to start and number of columns to get
different_names_pos = {
    "Key lengths": (1, 2)
}

# If a sheet has some columns that should be considered as guideline "versions" but don't use the usual syntax they
# can be set in a list in a dictionary with "guideline": [col_index1, col_index2] that appears as a value for the
# respective sheet
sheet_columns = {
    "Cipher Suites": {
        "NIST": [1, 2, 3],
        "BSI": [1, 2]
    },
}

converters = {
    # this function is needed to avoid having iana codes in the form 0.0
    ('IANA', 'Unnamed: 1_level_1'): lambda x: str(int(x)) if isinstance(x, float) else str(x)
}
