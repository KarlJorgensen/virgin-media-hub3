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


def human(obj):
    if hasattr(obj, '__human__'):
        return obj.__human__()
    return str(obj)

def format_table(table_rows):
    """Print a table in a nice human-readable format.

    The table is expected to be a dict, where each key is the row ID,
    and the value is a dict. Each row in turn is also a dict, with the
    key as the column name.

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
    def column_values(colname):
        return map(human,
                   [row[colname] if row[colname] is not None else ""
                    for row in table_rows.values()
                    if colname in row ])

    column_names = list(unique_everseen([fieldname
                                         for row in table_rows.values()
                                         for fieldname in row.keys()
                                         if any(column_values(fieldname))
    ]))

    # print("Column names:", column_names)

    column_widths = {colname: max([len(colname)] + \
                                  list(map(len, column_values(colname))))
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
            res += ' ' + human(column_name).ljust(column_widths[column_name])
            res += ' |'
        return res

    def row_text(row):
        res = '|'
        for column_name in column_names:
            cellvalue = row.get(column_name)
            val = human(cellvalue) if cellvalue is not None else ""
            res += ' ' + val.ljust(column_widths[column_name])
            res += ' |'
        return res

    fmt = horiz_line() + "\n"
    fmt += row_header(column_names) + "\n"
    fmt += horiz_line() + "\n"

    for rowid, row in table_rows.items():
        # TODO: Show the row ID?
        fmt += row_text(row) + "\n"

    fmt += horiz_line() + "\n"
    return fmt

def format_by_row(table_rows):
    """Get a string representation of a table for human consumption.

    The table is expected to be a dict, where each key is the row ID,
    and the value is a dict. Each row in turn is also a dict, with the
    key as the column name.

    This lists each row as a sequence of lines, followed by the next
    row etc.  This format is well suited for tables with many columns
    and/or narrow terminals.

    """
    res = ""
    for rownum, (rowkey, row) in enumerate(table_rows.items(), start=0):
        if rownum:
            # Blank lines between rows
            res += "\n"
        res += format_one_row(rowkey, row)
    return res

def format_one_row(rowkey, row):
    """Produce a string representation of one row.

    This will list the attributes: one per line, with the name
    followed by the value (separated by a colon) - e.g.:

        name        : Subnet 1
        interfaces  : 9
        vlan        : 0
        passthrough : 2

    """
    res = "Row: " + rowkey + "\n"
    namelength = max([len(name) for name in row.keys()])
    for name, value in row.items():
        res += "  " + name.ljust(namelength) + " : " + human(value) + "\n"
    return res

if __name__ == "__main__":

    print(format_table(
        {"1": {"country": "Denmark",
               "language": "Danish",
               "Lego": "quite awesome",
               "Intellibility/Readability": 11},
         "2": {"country": "Sweden",
               "language": "Swedish",
               "Crazy": True},
         "8": {"language": "Python",
               "Crazy": 0.5,
               "Intellibility/Readability": True},
        }))
