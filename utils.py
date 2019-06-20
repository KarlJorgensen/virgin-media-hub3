#!/usr/bin/python3
"""Misc utilities that did not fit anywhere nicely.

These are intended for internal use only: The API is subject to
change.

"""
import functools
import itertools

def debug(func):
    """A function decorator that will print function calls and their results"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        print("calling {0}(args={1}, kwargs={2})".format(func, args, kwargs))
        res = func(*args, **kwargs)
        print("{f}(args={a}, kwargs={kw}) => {res}".format(f=func.__name__,
                                                           a=args,
                                                           kw=kwargs,
                                                           res=res))
        return res
    return wrapper

def unique_everseen(iterable, key=None):
    "List unique elements, preserving order. Remember all elements ever seen."
    # unique_everseen('AAAABBBCCDAABBB') --> A B C D
    # unique_everseen('ABBCcAD', str.lower) --> A B C D
    seen = set()
    seen_add = seen.add
    if key is None:
        for element in itertools.filterfalse(seen.__contains__, iterable):
            seen_add(element)
            yield element
    else:
        for element in iterable:
            k = key(element)
            if k not in seen:
                seen_add(k)
                yield element

def format_table(table_rows):
    """Print a list of dicts in a nice human-readable format.

    This is mostly useful for development - e.g. printing snmp
    table_rows things, but might be useful for other things too...

    The resulting string (including newlines) can look like this:

        +-------------+--------+---------------+-----------------------------------------+
        | IPAddr      | Prefix | NetMask       | GW                                      |
        +-------------+--------+---------------+-----------------------------------------+
        | 86.21.83.42 | 21     | 255.255.248.0 | 86.21.80.1                              |
        |             | 0      |               | 0000:000c:000f:cea0:000f:caf0:0000:0000 |
        +-------------+--------+---------------+-----------------------------------------+
    """
    column_names = list(unique_everseen([fieldname
                                         for row in table_rows
                                         for fieldname in row.keys()]))

    # print("Column names:", column_names)

    column_widths = {colname: max([len(colname)] + \
                                  list(map(len,
                                           map(str,
                                               [getattr(row, colname)
                                                for row in table_rows
                                                if hasattr(row, colname)] \
                                               + [row[colname]
                                                  for row in table_rows
                                                  if isinstance(row, dict) and colname in row]))))
                     for colname in column_names}

    # print("Columnn widths:", column_widths)

    def horiz_line(vbar="+"):
        res = vbar
        for column_name in column_names:
            res += "-"
            res += "-" * column_widths[column_name]
            res += "-" + vbar
        return res

    def row_header(column_names):
        res = '|'
        for column_name in column_names:
            res += ' ' + str(column_name).ljust(column_widths[column_name])
            res += ' |'
        return res

    def row_text(row):
        res = '|'
        for column_name in column_names:
            if hasattr(row, column_name):
                cellvalue = getattr(row, column_name)
                val = str(cellvalue) if cellvalue is not None else ""
            elif column_name in row.keys():
                cellvalue = row[column_name]
                val = str(cellvalue) if cellvalue is not None else ""
            else:
                val = ""
            res += ' ' + val.ljust(column_widths[column_name])
            res += ' |'
        return res

    fmt = horiz_line() + "\n"
    fmt += row_header(column_names) + "\n"
    fmt += horiz_line() + "\n"

    for row in table_rows:
        fmt += row_text(row) + "\n"

    fmt += horiz_line() + "\n"
    return fmt

def format_by_row(table_rows):
    """Get a string representation of a table for human consumption.

    This lists each row as a sequence of lines, followed by the next
    row etc.  This format is well suited for tables with many columns
    and/or narrow terminals.

    """
    res = ""
    for rownum, row in enumerate(table_rows, start=0):
        if rownum:
            # Blank lines between rows
            res += "\n"
        res += format_one_row(row)
    return res

def format_one_row(row):
    """Produce a string representation of one row.

    This will list the attributes: one per line, with the name
    followed by the value (separated by a colon) - e.g.:

        name        : Subnet 1
        interfaces  : 9
        vlan        : 0
        passthrough : 2

    """
    res = ""
    namelength = max([len(name) for name in row.keys()])
    for name, value in row.items():
        res += name.ljust(namelength) + " : " + str(value) + "\n"
    return res

if __name__ == "__main__":

    print(format_table(
        [{"country": "Denmark",
          "language": "Danish",
          "Lego": "quite awesome",
          "Intellibility/Readability": 11},
         {"country": "Sweden",
          "language": "Swedish",
          "Crazy": True},
         {"language": "Python",
          "Crazy": 0.5,
          "Intellibility/Readability": True},
        ]))
