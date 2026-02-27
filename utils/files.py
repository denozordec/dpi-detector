import os
import sys
import json

from cli.console import console


def get_exe_dir() -> str:
    """Директория рядом с .exe или точкой входа при запуске напрямую."""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    # __file__ здесь — utils/files.py, поднимаемся на уровень выше к корню проекта
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def get_resource_path(relative_path: str) -> str:
    """Ищет файл рядом с exe/скриптом, затем внутри PyInstaller-бандла."""
    external = os.path.join(get_exe_dir(), relative_path)
    if os.path.exists(external):
        return external

    try:
        bundled = os.path.join(sys._MEIPASS, relative_path)
        if os.path.exists(bundled):
            return bundled
    except AttributeError:
        pass

    return external


def load_domains(filepath: str = "domains.txt") -> list[str]:
    full_path = get_resource_path(filepath)

    if not os.path.exists(full_path):
        console.print(f"[bold red]КРИТИЧЕСКАЯ ОШИБКА: Файл не найден![/bold red]")
        console.print(f"[red]Путь: {full_path}[/red]")
        console.print("[yellow]Положите domains.txt рядом со скриптом.[/yellow]")
        sys.exit(1)

    try:
        with open(full_path, 'r', encoding='utf-8') as f:
            return [
                line.strip() for line in f
                if line.strip() and not line.startswith('#')
            ]
    except Exception as e:
        console.print(f"[bold red]Ошибка чтения файла {filepath}: {e}[/bold red]")
        sys.exit(1)


def load_tcp_targets(filepath: str = "tcp_16_20_targets3.json") -> list:
    full_path = get_resource_path(filepath)

    if not os.path.exists(full_path):
        console.print(f"[bold red]КРИТИЧЕСКАЯ ОШИБКА: Файл не найден![/bold red]")
        console.print(f"[red]Путь: {full_path}[/red]")
        sys.exit(1)

    try:
        with open(full_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        console.print(f"[bold red]ОШИБКА: Некорректный JSON в {filepath}![/bold red]")
        console.print(f"[red]{e}[/red]")
        sys.exit(1)