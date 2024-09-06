#!/usr/bin/python3
#Created by Miguel Rios
import typer
from enum import Enum
from pathlib import Path
from mesa_toolkit.logger import init_logger, logger, console
from mesa_toolkit import __version__
from mesa_toolkit.lib.mesa_scans import *

app = typer.Typer(
    add_completion=False,
    rich_markup_mode='rich',
    context_settings={'help_option_names': ['-h', '--help']},
    pretty_exceptions_show_locals=False
)

class Operations(str, Enum):
    scoper = "scoper"
    masscan = "masscan"
    discovery = "discovery"
    full = "full"
    aquatone = "aquatone"
    encryption_check = "encryption_check"
    default_logins = "default_logins"
    smb_signing_check = "smb_signing_check"
    vuln_scans = "vuln_scans"
    all_checks = "all_checks"
    report_generator = "report_generator"
    json_generator = "json_generator"


@app.command(no_args_is_help=True, help='MESA-Toolkit help!')
def main(
    operation: Operations = typer.Option(..., '--operation', '-o',
        help='Operation to be run'),
    project_name: str = typer.Option(..., '--project-name', '-p', help='Set project name'),
    input_file: Path = typer.Option(
        None, '--input-file', '-i', exists=True, file_okay=True, dir_okay=False,
        readable=True, resolve_path=True, help='Set input file'),
    exclude_file: Path = typer.Option(
        None, '--exclude-file', '-e', exists=True, file_okay=True, dir_okay=False,
        readable=True, resolve_path=True, help='Set exclude file'),
    customer_name: str = typer.Option(
        None, '--customer-name', '-cn', help='Set customer long name for report generator'),
    customer_initials: str = typer.Option(
        None, '--customer-initials', '-ci', help='Set customer initials for report generator'),   
    debug: bool = typer.Option(False, '--debug', help='Enable [green]DEBUG[/] output')):

    init_logger(debug)

    if input_file:
        input_file=str(input_file)

    if exclude_file:
        exclude_file=str(exclude_file)

    if operation == Operations.scoper:
        scoper(project_name, input_file, exclude_file)

    if operation == Operations.masscan:
        masscan(project_name, input_file, exclude_file)

    if operation == Operations.discovery:
        discovery(project_name, input_file, exclude_file)

    if operation == Operations.full:
        full_port(project_name, input_file, exclude_file)

    if operation == Operations.aquatone:
        aquatone(project_name, input_file, exclude_file)

    if operation == Operations.encryption_check:
        encryption_check(project_name, input_file, exclude_file)

    if operation == Operations.default_logins:
        default_logins(project_name, input_file, exclude_file)

    if operation == Operations.smb_signing_check:
        smb_signing_check(project_name, input_file, exclude_file)

    if operation == Operations.vuln_scans:
        vuln_scans(project_name, input_file, exclude_file)

    if operation == Operations.all_checks:
        all_checks(project_name, input_file, exclude_file)

    if operation == Operations.report_generator:
        report_generator(project_name, customer_name, customer_initials)

    if operation == Operations.json_generator:
        json_generator(project_name, customer_name, customer_initials)

if __name__ == '__main__':
    app(prog_name='MESA-Toolkit')
