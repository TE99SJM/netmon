"""CSV exports that treat device-supplied names as text in spreadsheets."""
import csv


def safe_cell(value):
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r", "\n")):
        return "'" + value
    return "" if value is None else value


def write_csv(path, headings, rows):
    with open(path, "w", newline="", encoding="utf-8-sig") as output:
        writer = csv.writer(output)
        writer.writerow(headings)
        writer.writerows([safe_cell(value) for value in row] for row in rows)
