from pathlib import Path

from markdown2 import markdown
from pdfkit import from_file  # import python module
from os.path import exists
from os import remove
import codecs

H1 = 1
H2 = 2
H3 = 3
H4 = 4
H5 = 5


class Class_table:
    """
    Class to create table in markdown
    """

    def wrap(self, wrap):
        """
        Wrap text in table

        :param wrap: String to wrap
        :type wrap: str
        :return: Wrapped string
        :rtype: str
        """
        return f"| {wrap} |"

    def heading(self):
        """
        Create a table header

        :return: Table header
        :rtype: str
        """
        return self.wrap("-------")

    def bold(self, string):
        """
        Create bold text in table

        :param string: String to bold
        :type string: str
        :return: Bolded string
        :rtype: str
        """
        return self.wrap(bold(string))

    def italic(self, string):
        """
        Create italic text in table

        :param string: String to italic
        :type string: str
        :return: Italicized string
        :rtype: str
        """
        return self.wrap(italic(string))

    def title(self, string):
        """
        Create title text in table

        :param string: String to title
        :type string: str
        :return: Titled string
        :rtype: str
        """
        return self.bold(string)


table = Class_table()


def recursive_parsing(value, hlevel: int, bold_instead: bool) -> str:
    """
    Parse the output and prepare md for the report recursively.

    :param value: The object to prepare as output
    :param hlevel: The height level
    :type hlevel: int
    :param bold_instead: Instead of using H1, H2, H3, ... use a simple bold in markdown.
    :type bold_instead: bool
    :return: String to insert into the md file.
    :rtype: str
    """
    return __recursive_parsing_runner(value, hlevel, hlevel, bold_instead)


def __repeat_to_length(string_to_expand: str, length: int) -> str:
    """
    Repeat a string to a given times.

    :param string_to_expand: The string to repeat.
    :type string_to_expand: str
    :param length: The times to repeat.
    :type length: int
    :return: Formatted String.
    :rtype: str
    """
    return (string_to_expand * (int(length / len(string_to_expand)) + 1))[:length]


def __recursive_parsing_runner(
    value, hlevel: int, initial_hlevel: int, bold_instead: bool, is_code=False
):
    """
    Internal function to recursively parse the output and prepare md for the report.

    :param value: The object to prepare as output
    :type value: Any
    :param hlevel: The height level
    :type hlevel: int
    :param initial_hlevel: The initial height level
    :type initial_hlevel: int
    :param bold_instead: Instead of using H1, H2, H3, ... use a simple bold in markdown.
    :type bold_instead: bool
    :param is_code: If the value is a code (e.g. a function).
    :type is_code: bool
    :return: String to insert into the md file.
    :rtype: str
    """
    results = []

    if isinstance(value, list):
        for v in value:
            results.append(
                __recursive_parsing_runner(
                    v, hlevel + 1, initial_hlevel, bold_instead, is_code
                )
            )
    elif isinstance(value, dict):
        for k, v in value.items():
            if hlevel > 6:
                hlevel = 6
            if hlevel < 1:
                hlevel = 1

            rec_result = __recursive_parsing_runner(
                v, hlevel + 1, initial_hlevel, bold_instead, is_code=("code" in k)
            )
            if (v or v is False) and (rec_result or rec_result is False):
                prepend = "- "
                results.append(
                    f"{prepend}{title(k, hlevel) if not bold_instead else bold(k)}"
                )

                results.append(rec_result)
    else:
        results.append(
            f"{__repeat_to_length('    ', hlevel - initial_hlevel + 1)}- {value}"
            if not is_code
            else multiline_code(value)
        )
    return "\n".join(results)


def html_to_pdf(source_path: str, output_filename: str, delete_html=True):
    """
    Convert an HTML file to PDF.

    :param source_path: The input HTML file path
    :type source_path: str
    :param output_filename: The output PDF file path
    :type source_path: str
    :param delete_html: Delete HTML file after doing the conversion. Default: True
    :type delete_html: bool
    """
    # open output file for writing (truncated binary)
    assert exists(source_path), "The input file MUST exists!"
    from_file(source_path, output_filename)
    if delete_html:
        remove(source_path)
        # return False on success and True on errors


def md_to_html(
    extras: list, results: str, output_file: str or Path = "output.html", css_file=None
):
    """
    Convert an md string to HTML file.

    :param results: The results from the computation.
    :type results:dict
    :param extras: Extras of Markdown2 (check wiki)
    :type extras: list of str
    :param output_file: output file path
    :type output_file: str
    :param css_file: CSS file path to beautify the HTML output.
    :type css_file: str
    """
    with open(output_file, "w") as file:
        if css_file:
            with open(css_file, "r") as style:
                out = """<!DOCTYPE html>
                                <html lang="en">
    
                                <head>
                                    <meta charset="utf-8">
                                    <style type="text/css">
                      """
                file.write(out)

                for s in style:
                    file.write(s)
                file.write("</style></head><body style ='overflow-x: scroll'>")
                file.write(markdown(results, extras=extras))
                file.write("</body></html>")
        else:
            file.write(markdown(results, extras=extras))


def title(string: str, level=H1) -> str:
    """
    Add title md style.

    :param string: The string to process.
    :type string:str
    :param level: depth level for the header (h1,h2,h3..)
    :type level: int
    :return: Formatted String.
    :rtype: str
    """
    appended = []
    for lvl in range(0, level):
        appended.append("#")
    return f"{''.join(appended)} {string}"


def bold(string: str) -> str:
    """
    Add bold md style.

    :param string: The string to process.
    :type string:str
    :return: Formatted String.
    :rtype: str
    """
    return f"**{string}**"


def line() -> str:
    """
    Add line md style.

    :return: Formatted line in md style.
    :rtype: str
    """
    return f"---"


def italic(string: str) -> str:
    """
    Add italic md style.

    :param string: The string to process.
    :type string:str
    :return: Formatted String.
    :rtype: str
    """
    return f"*{string}*"


def code(string: str) -> str:
    """
    Add code md style.

    :param string: The string to process.
    :type string:str
    :return: Formatted String.
    :rtype: str
    """
    return f"`{string}`"


def multiline_code(string: str, language=None) -> str:
    """
    Add multiline code md style.

    :param language: Language of the code (default NONE)
    :param string: The string to process.
    :type string:str
    :return: Formatted String.
    :rtype: str
    """
    return f"```{language if language else ''}\n {string} \n```"
