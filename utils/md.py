from markdown2 import markdown

H1 = 1
H2 = 2
H3 = 3
H4 = 4
H5 = 5


def recursive_parsing(value, hlevel: int) -> str:
    results = []
    if isinstance(value, list):
        for v in value:
            results.append(recursive_parsing(v, hlevel + 1))
    elif isinstance(value, dict):
        for k, v in value.items():
            if hlevel > 6:
                hlevel = 6
            if hlevel < 1:
                hlevel = 1
            header = "".join(["#" for i in range(0, hlevel)])
            results.append(f"{header} {k}")
            results.append(recursive_parsing(v, hlevel + 1))
    else:
        results.append(value)
    return "\n".join(results)


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
