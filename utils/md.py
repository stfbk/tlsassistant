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


def recursive_parsing(value, hlevel: int, bold_instead: bool) -> str:
    return __recursive_parsing_runner(value, hlevel, hlevel, bold_instead)


def __repeat_to_length(string_to_expand, length):
    return (string_to_expand * (int(length / len(string_to_expand)) + 1))[:length]


def __recursive_parsing_runner(
    value, hlevel: int, initial_hlevel: int, bold_instead: bool, is_code=False
):
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
                # prepend = __repeat_to_length('    ', hlevel - initial_hlevel) + '- ' if hlevel != initial_hlevel else ''
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
    # open output file for writing (truncated binary)
    assert exists(source_path), "The input file MUST exists!"
    from_file(source_path, output_filename)
    if delete_html:
        remove(source_path)
        # return False on success and True on errors


def md_to_html(extras, results, output_file="output.html", css_file=None):
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
                file.write("</style></head><body>")
                file.write(markdown(results, extras=extras))
                file.write("</body></html>")
        else:
            file.write(markdown(results, extras=extras))


def title(string, level=H1):
    appended = []
    for lvl in range(0, level):
        appended.append("#")
    return f"{''.join(appended)} {string}"


def bold(string):
    return f"**{string}**"


def line():
    return f"---"


def italic(string):
    return f"*{string}*"


def code(string):
    return f"`{string}`"


def multiline_code(string, language=None):
    return f"```{language if language else ''} {string} ```"
