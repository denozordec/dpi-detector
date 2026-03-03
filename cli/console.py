from rich.console import Console

# record=False по умолчанию — не буферизируем вывод в памяти.
# Включается в True только в dpi_detector.py при save_to_file=True.
console = Console(record=False, force_terminal=True, force_jupyter=False, width=220)
