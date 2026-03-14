# main.py

import logging
import configparser
from pathlib import Path
from typing import List, Optional
from textwrap import dedent
import sys  # ADICIONADO
import os   # ADICIONADO

import typer
import keyring
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table

from threatdeflect.core import engine
from threatdeflect.core.engine import AnalysisError, NoValidTargetsError
from threatdeflect.utils.utils import is_file_writable, parse_repo_urls, get_config_path, get_log_path
from threatdeflect.api.api_client import ApiClient
from threatdeflect.ui.translations import T, translator
import click

# --- i18n: Translate Click/Typer internal labels to match active language ---
if translator.language == "pt_br":
    _orig_write_heading = click.HelpFormatter.write_heading
    _PT_HEADINGS = {
        "Options": "Opções",
        "Commands": "Comandos",
        "Arguments": "Argumentos",
    }

    def _i18n_heading(self, heading):
        return _orig_write_heading(self, _PT_HEADINGS.get(heading, heading))
    click.HelpFormatter.write_heading = _i18n_heading

    _orig_write_usage = click.HelpFormatter.write_usage

    def _i18n_usage(self, prog, args="", prefix=None):
        return _orig_write_usage(self, prog, args, prefix=("Uso: " if prefix is None else prefix))
    click.HelpFormatter.write_usage = _i18n_usage

    _orig_get_help_option = click.Command.get_help_option

    def _i18n_help_option(self, ctx):
        opt = _orig_get_help_option(self, ctx)
        if opt is not None:
            opt.help = "Mostra esta mensagem e encerra."
        return opt
    click.Command.get_help_option = _i18n_help_option

    _orig_multi_format_usage = click.MultiCommand.format_usage

    def _i18n_multi_format_usage(self, ctx, formatter):
        orig_opts, orig_sub = self.options_metavar, self.subcommand_metavar
        self.options_metavar = "[OPÇÕES]"
        self.subcommand_metavar = "COMANDO [ARGS]..."
        _orig_multi_format_usage(self, ctx, formatter)
        self.options_metavar, self.subcommand_metavar = orig_opts, orig_sub
    click.MultiCommand.format_usage = _i18n_multi_format_usage

    _orig_collect_usage = click.Command.collect_usage_pieces

    def _i18n_collect_usage(self, ctx):
        pieces = _orig_collect_usage(self, ctx)
        return ["[OPÇÕES]" if p == "[OPTIONS]" else p for p in pieces]
    click.Command.collect_usage_pieces = _i18n_collect_usage

    # Patch Typer's Rich panel titles (Options/Commands/Arguments boxes)
    try:
        from typer import rich_utils
        _orig_panel_title = getattr(rich_utils, '_get_rich_console', None)
        # Typer uses these module-level constants for panel titles
        if hasattr(rich_utils, 'STYLE_OPTIONS_PANEL_BORDER'):
            _PT_PANELS = {
                "Options": "Opções",
                "Commands": "Comandos",
                "Arguments": "Argumentos",
                "Default": "Padrão",
            }
            _orig_make_rich_text = rich_utils._make_rich_rext if hasattr(rich_utils, '_make_rich_rext') else None

            _orig_get_help_text = rich_utils._get_help_text if hasattr(rich_utils, '_get_help_text') else None

            # Monkey-patch the Rich help rendering to translate panel titles
            import rich.panel
            _orig_panel_init = rich.panel.Panel.__init__

            def _i18n_panel_init(self, *args, **kwargs):
                if 'title' in kwargs and isinstance(kwargs['title'], str):
                    kwargs['title'] = _PT_PANELS.get(kwargs['title'], kwargs['title'])
                _orig_panel_init(self, *args, **kwargs)
            rich.panel.Panel.__init__ = _i18n_panel_init
    except (ImportError, AttributeError):
        pass


if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
   
    
    if len(sys.argv) == 1 and not sys.stdout.isatty():
        try:
            import tkinter as tk
            from tkinter import messagebox

            root = tk.Tk()
            root.withdraw()  

            messagebox.showinfo(
                "ThreatDeflect CLI",
                "Esta é a versão de linha de comando (CLI) do ThreatDeflect.\n\n"
                "Para usar, abra um terminal (cmd, PowerShell, etc.), navegue até esta pasta e execute o comando:\n\n"
                "threatdeflect --help"
            )
            sys.exit(0) 
        except Exception as e:
            
            logging.basicConfig(filename='threatdeflect_popup_error.log', level=logging.INFO)
            logging.error("Falha ao criar o pop-up de ajuda: %s", e)
            sys.exit(1)




main_epilog = dedent(f"""
    [bold]{T('cli_main_epilog_apis')}[/bold]  {T('cli_main_epilog_api_list')}
    [bold]{T('cli_main_epilog_ai')}[/bold]     {T('cli_main_epilog_ai_desc')}
    [bold]{T('cli_main_epilog_gui')}[/bold]       {T('cli_main_epilog_gui_desc')}

    [bold]{T('cli_help_more_info')}[/bold]
      [green]$ threatdeflect [COMMAND] --help[/green]
""")

ioc_examples = dedent(f"""
    [bold]{T('cli_examples_title')}[/bold]

      [cyan]# {T('cli_ioc_example1_desc')}[/cyan]
      [green]$ threatdeflect ioc 8.8.8.8 https://malware.com/payload.php --ai llama3[/green]

      [cyan]# {T('cli_ioc_example2_desc')}[/cyan]
      [green]$ threatdeflect ioc --file targets.txt[/green]

      [cyan]# {T('cli_ioc_example3_desc')}[/cyan]
      [green]$ threatdeflect ioc 1.1.1.1 -o report_cloudflare.xlsx[/green]

      [cyan]# {T('cli_ioc_example4_desc')}[/cyan]
      [green]$ threatdeflect ioc 8.8.8.8 1.1.1.1 https://example.com https://test.org[/green]
""")

repo_examples = dedent(f"""
    [bold]{T('cli_examples_title')}[/bold]

      [cyan]# {T('cli_repo_example1_desc')}[/cyan]
      [green]$ threatdeflect repo https://github.com/some/repo --ai mistral[/green]

      [cyan]# {T('cli_repo_example2_desc')}[/cyan]
      [green]$ threatdeflect repo https://github.com/org/repo1 https://github.com/org/repo2[/green]

      [cyan]# {T('cli_repo_example3_desc')}[/cyan]
      [green]$ threatdeflect repo https://github.com/some/repo -o audit_results.xlsx[/green]
""")

config_examples = dedent(f"""
    [bold]{T('cli_examples_title')}[/bold]

      [cyan]# {T('cli_config_example1_desc')}[/cyan]
      [green]$ threatdeflect config set virustotal YOUR_KEY_HERE[/green]

      [cyan]# {T('cli_config_example2_desc')}[/cyan]
      [green]$ threatdeflect config set-ollama http://localhost:11434/api/generate[/green]

      [cyan]# {T('cli_config_example3_desc')}[/cyan]
      [green]$ threatdeflect config set-log-path /var/logs/threatdeflect.log[/green]
      
      [cyan]# {T('cli_config_example4_desc')}[/cyan]
      [green]$ threatdeflect config set-lang pt_br[/green]

      [cyan]# {T('cli_config_example5_desc')}[/cyan]
      [green]$ threatdeflect config show[/green]
""")


app = typer.Typer(
    name="threatdeflect",
    help=T('cli_app_help'),
    epilog=main_epilog,
    add_completion=False,
    rich_markup_mode="rich"
)
console = Console()


config_app = typer.Typer(
    name="config",
    help=T('cli_config_app_help'),
    epilog=config_examples,
    rich_markup_mode="rich"
)
app.add_typer(config_app)


def cli_log_callback(message: str) -> None:
    """Callback para imprimir logs na consola, usado pelo motor."""
    logging.info(message)
    console.log(f"[dim]{T('cli_log_engine_prefix')}[/] {message}")


@app.command(
    name="ioc",
    help=T('cli_ioc_command_help'),
    epilog=ioc_examples
)
def analyze_iocs(
    targets: Optional[List[str]] = typer.Argument(None, help=T('cli_ioc_arg_targets_help')),
    input_file: Optional[Path] = typer.Option(
        None, "--file", "-f",
        help=T('cli_ioc_option_file_help'),
        exists=True, file_okay=True, dir_okay=False, readable=True
    ),
    output: Path = typer.Option(
        "Analise_IOCs.xlsx", "--output", "-o",
        help=T('cli_ioc_option_output_help'),
        writable=True, dir_okay=False
    ),
    ai_model: Optional[str] = typer.Option(
        None, "--ai",
        help=T('cli_option_ai_help')
    )
) -> None:
    all_targets = []
    if targets:
        all_targets.extend(targets)
    if input_file:
        console.print(f":page_facing_up: {T('cli_reading_targets_from')} [cyan]{input_file.name}[/cyan]")
        all_targets.extend(input_file.read_text(encoding='utf-8').splitlines())

    if not all_targets:
        console.print(f"[bold red]{T('cli_error_prefix')}[/] {T('cli_error_no_targets')}")
        raise typer.Exit(code=1)

    console.print(f":mag: {T('cli_analyzing_targets', count=len(all_targets))}")
    
    if not is_file_writable(str(output)):
        console.print(f"[bold red]{T('cli_error_prefix')}[/] {T('cli_error_cannot_write_to', file=output)}")
        raise typer.Exit(code=1)

    try:
        with console.status(f"[bold green]{T('cli_status_processing')}...", spinner="dots") as status:
            def progress_callback(current: int, total: int) -> None:
                status.update(f"[bold green]{T('cli_status_processing')}... {current}/{total}")
            
            results = engine.run_ioc_analysis(
                "\n".join(all_targets), output, cli_log_callback, progress_callback
            )

        console.print(f"\n[bold green]{T('cli_analysis_success')}[/]")
        console.print(f"{T('cli_report_saved_to')} [link=file://{output.resolve()}]{output}[/link]")
        
        if ai_model:
            with console.status(f"[bold magenta]{T('cli_status_generating_summary', model=ai_model)}...", spinner="moon"):
                summary = engine.get_ai_summary(results, ai_model, cli_log_callback)
            console.rule(f"[bold magenta]{T('cli_summary_title', model=ai_model)}")
            console.print(Markdown(summary))
            console.rule()

    except NoValidTargetsError:
        console.print(f"\n[bold yellow]{T('cli_warning_prefix')}[/] {T('cli_warning_no_valid_targets')}")
    except AnalysisError:
        console.print(f"\n[bold red]{T('cli_analysis_failed')}[/]")
        raise typer.Exit(code=1)

file_examples = dedent(f"""
    [bold]{T('cli_examples_title')}[/bold]

      [cyan]# {T('cli_file_example1_desc')}[/cyan]
      [green]$ threatdeflect file suspicious.exe malware.dll --ai llama3[/green]

      [cyan]# {T('cli_file_example2_desc')}[/cyan]
      [green]$ threatdeflect file /path/to/suspicious_file.bin[/green]

      [cyan]# {T('cli_file_example3_desc')}[/cyan]
      [green]$ threatdeflect file ransomware.exe -o file_audit.xlsx[/green]
""")

@app.command(
    name="file",
    help=T('cli_file_command_help'),
    epilog=file_examples
)
def analyze_files(
    files: List[Path] = typer.Argument(..., help=T('cli_file_arg_files_help')),
    output: Path = typer.Option(
        "Analise_Arquivos.xlsx", "--output", "-o",
        help=T('cli_file_option_output_help'),
        writable=True, dir_okay=False
    ),
    ai_model: Optional[str] = typer.Option(
        None, "--ai",
        help=T('cli_option_ai_help')
    )
) -> None:
    for f in files:
        if not f.exists() or not f.is_file():
            console.print(f"[bold red]{T('cli_error_prefix')}[/] {T('cli_error_file_not_found', file=f)}")
            raise typer.Exit(code=1)

    console.print(f":microscope: {T('cli_analyzing_files', count=len(files))}")

    if not is_file_writable(str(output)):
        console.print(f"[bold red]{T('cli_error_prefix')}[/] {T('cli_error_cannot_write_to', file=output)}")
        raise typer.Exit(code=1)

    try:
        with console.status(f"[bold green]{T('cli_status_processing')}...", spinner="dots") as status:
            def progress_callback(current: int, total: int) -> None:
                status.update(f"[bold green]{T('cli_status_processing')}... {current}/{total}")

            results = engine.run_file_analysis(
                [str(f) for f in files], output, cli_log_callback, progress_callback
            )

        console.print(f"\n[bold green]{T('cli_analysis_success')}[/]")
        console.print(f"{T('cli_report_saved_to')} [link=file://{output.resolve()}]{output}[/link]")

        if ai_model:
            with console.status(f"[bold magenta]{T('cli_status_generating_summary', model=ai_model)}...", spinner="moon"):
                summary = engine.get_ai_summary(results, ai_model, cli_log_callback)
            console.rule(f"[bold magenta]{T('cli_summary_title', model=ai_model)}")
            console.print(Markdown(summary))
            console.rule()

    except NoValidTargetsError:
        console.print(f"\n[bold yellow]{T('cli_warning_prefix')}[/] {T('cli_warning_no_valid_files')}")
    except AnalysisError:
        console.print(f"\n[bold red]{T('cli_analysis_failed')}[/]")
        raise typer.Exit(code=1)

@app.command(
    name="repo",
    help=T('cli_repo_command_help'),
    epilog=repo_examples
)
def analyze_repos(
    urls: List[str] = typer.Argument(..., help=T('cli_repo_arg_urls_help')),
    output: Path = typer.Option(
        "Analise_Repositorios.xlsx", "--output", "-o",
        help=T('cli_repo_option_output_help'),
        writable=True, dir_okay=False
    ),
    ai_model: Optional[str] = typer.Option(
        None, "--ai",
        help=T('cli_option_ai_help')
    )
) -> None:
    valid_urls, _, _ = parse_repo_urls("\n".join(urls))
    if not valid_urls:
        console.print(f"[bold red]{T('cli_error_prefix')}[/] {T('cli_error_no_valid_repos')}")
        raise typer.Exit(code=1)
        
    console.print(f":package: {T('cli_analyzing_repos', count=len(valid_urls))}")

    try:
        with console.status(f"[bold green]{T('cli_status_processing')}...", spinner="dots") as status:
            def progress_callback(current: int, total: int) -> None:
                status.update(f"[bold green]{T('cli_status_analyzing_repos')}... {current}/{total}")

            results = engine.run_repo_analysis(
                valid_urls, output, cli_log_callback, progress_callback
            )
        
        console.print(f"\n[bold green]{T('cli_analysis_success')}[/]")
        console.print(f"{T('cli_report_saved_to')} [link=file://{output.resolve()}]{output}[/link]")

        if ai_model and results:
            with console.status(f"[bold magenta]{T('cli_status_generating_summary', model=ai_model)}...", spinner="moon"):
                summary = engine.get_ai_summary(results, ai_model, cli_log_callback)
            console.rule(f"[bold magenta]{T('cli_summary_title', model=ai_model)}")
            console.print(Markdown(summary))
            console.rule()
    except AnalysisError:
        console.print(f"\n[bold red]{T('cli_analysis_failed')}[/]")
        raise typer.Exit(code=1)


KEYRING_MAP = {
    "virustotal": "virustotal_api_key", "abuseipdb": "abuseipdb_api_key",
    "urlhaus": "urlhaus_api_key", "shodan": "shodan_api_key",
    "malwarebazaar": "malwarebazaar_api_key", "github": "github_api_key",
    "gitlab": "gitlab_api_key",
}

@config_app.command("set", help=T('cli_config_set_help'))
def set_key(
    service: str = typer.Argument(..., help=T('cli_config_set_arg_service_help', services=', '.join(KEYRING_MAP.keys()))),
    key: str = typer.Argument(..., help=T('cli_config_set_arg_key_help'))
):
    service_lower = service.lower()
    if service_lower not in KEYRING_MAP:
        console.print(f"[bold red]{T('cli_error_prefix')}[/] {T('cli_error_invalid_service', service=service)}")
        raise typer.Exit(code=1)
    
    keyring.set_password("vtotalscan", KEYRING_MAP[service_lower], key)
    console.print(f"[bold green]{T('cli_success_prefix')}[/] {T('cli_success_key_saved', service=service_lower)}")

@config_app.command("set-ollama", help=T('cli_config_set_ollama_help'))
def set_ollama_endpoint(
    endpoint: str = typer.Argument(..., help=T('cli_config_set_ollama_arg_endpoint_help'))
):
    config_path = get_config_path()
    config = configparser.ConfigParser()
    config.read(config_path)
    if not config.has_section('AI'):
        config.add_section('AI')
    config.set('AI', 'endpoint', endpoint)
    with open(config_path, 'w') as configfile:
        config.write(configfile)
    console.print(f"[bold green]{T('cli_success_prefix')}[/] {T('cli_success_ollama_endpoint', endpoint=endpoint)}")

@config_app.command("set-log-path", help=T('cli_config_set_log_path_help'))
def set_log_path(
    path: Path = typer.Argument(..., help=T('cli_config_set_log_path_arg_path_help'))
):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not is_file_writable(str(path)):
            console.print(f"[bold red]{T('cli_error_prefix')}[/] {T('cli_error_path_not_writable', path=path)}")
            raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]{T('cli_error_prefix')}[/] {T('cli_error_validating_path', path=path, error=e)}")
        raise typer.Exit(code=1)

    config_path = get_config_path()
    config = configparser.ConfigParser()
    config.read(config_path)
    if not config.has_section('General'):
        config.add_section('General')
    config.set('General', 'log_path', str(path.resolve()))
    with open(config_path, 'w') as configfile:
        config.write(configfile)
    console.print(f"[bold green]{T('cli_success_prefix')}[/] {T('cli_success_log_path_set', path=path.resolve())}")

@config_app.command("set-lang", help=T('cli_config_set_lang_help'))
def set_language(
    language_code: str = typer.Argument(..., help=T('cli_config_set_lang_arg_code_help'))
):
    supported_langs = ["pt_br", "en_us"]
    lang_lower = language_code.lower()

    if lang_lower not in supported_langs:
        console.print(f"[bold red]{T('cli_error_prefix')}[/] {T('cli_error_lang_not_supported', lang=language_code, supported_langs=', '.join(supported_langs))}")
        raise typer.Exit(code=1)

    config_path = get_config_path()
    config = configparser.ConfigParser()
    config.read(config_path)
    if not config.has_section('General'):
        config.add_section('General')
    
    config.set('General', 'language', lang_lower)
    with open(config_path, 'w') as configfile:
        config.write(configfile)
    
    console.print(f"[bold green]{T('cli_success_prefix')}[/] {T('cli_success_lang_set', lang=lang_lower)}")

@config_app.command("show", help=T('cli_config_show_help'))
def show_config():
    table = Table(T('cli_config_table_header_setting'), T('cli_config_table_header_status'), show_lines=True)
    
    for service, key_name in KEYRING_MAP.items():
        status = f"[green]{T('cli_status_configured')}[/green]" if keyring.get_password("vtotalscan", key_name) else f"[yellow]{T('cli_status_not_configured')}[/yellow]"
        table.add_row(f"{T('cli_api_key_for')} {service.capitalize()}", status)
    
    config_path = get_config_path()
    config = configparser.ConfigParser()
    config.read(config_path)
    
    log_path = config.get('General', 'log_path', fallback=str(get_log_path()))
    table.add_row(f"[bold]{T('cli_log_path')}[/bold]", log_path)
    
    language = config.get('General', 'language', fallback="pt_br")
    table.add_row(f"[bold]{T('cli_language')}[/bold]", language)

    endpoint = config.get('AI', 'endpoint', fallback=T('cli_status_not_configured'))
    table.add_row("Ollama Endpoint", endpoint)
    api_client = ApiClient()
    models = api_client.get_local_models()
    models_str = ", ".join(models) if models and "não encontrado" not in models[0].lower() else f"[yellow]{T('cli_ollama_no_models')}[/yellow]"
    table.add_row(T('cli_ollama_available_models'), models_str)
    
    console.print(table)


if __name__ == "__main__":
    app()