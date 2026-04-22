# Sigma to MaxPatrol SIEM Converter

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

Конвертер правил [Sigma](https://github.com/SigmaHQ/sigma) в формат корреляции **Positive Technologies MaxPatrol SIEM**.

Позволяет автоматически переводить открытые сигнатуры обнаружения угроз в синтаксис MaxPatrol, экономя часы ручного переноса правил SOC-аналитиками.

## 🔥 Возможности

- 🚀 Конвертация YAML Sigma-правил в `.krl` файлы MaxPatrol.
- 🧠 Маппинг полей Event Logs Windows на нормализованную схему MaxPatrol.
- 🏷️ Автоматическое определение важности (`importance`) на основе MITRE ATT&CK.
- 📦 Поддержка базовых логических операторов (`and`, `or`, `not`).
- 🛠️ Простая интеграция в CI/CD пайплайны SOC.

## 📦 Установка

```bash
git clone https://github.com/B1tBit/sigma-to-maxpatrol.git
cd sigma-to-maxpatrol
pip install -r requirements.txt
```

## ⚙️ Пример использования
```bash
python converter.py rules/example_rule.yml -o output/example_rule.krl
```
