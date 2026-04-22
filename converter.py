import yaml
import uuid
import argparse
import sys
import os
from field_mappings import SIGMA_TO_MAXPATROL_MAPPING, TACTIC_TO_IMPORTANCE

class SigmaToMaxPatrolConverter:
    def __init__(self, mapping=None, tactic_mapping=None):
        self.field_mapping = mapping or SIGMA_TO_MAXPATROL_MAPPING
        self.tactic_mapping = tactic_mapping or TACTIC_TO_IMPORTANCE

    def load_sigma_rule(self, file_path):
        # Логирование и парсинг правил
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading rule: {e}")
            sys.exit(1)

    def map_field(self, sigma_field):
        # Сопоставьте название поля Sigma с нормализованным названием поля MaxPatrol
        return self.field_mapping.get(sigma_field, sigma_field)

    def format_value(self, value):
        # Форматирование значения для выражения MaxPatrol
        if isinstance(value, bool):
            return str(value).lower()
        elif isinstance(value, (int, float)):
            return str(value)
        elif isinstance(value, list):
            # Обработка условий ИЛИ: ['value1', 'value2'] -> (field == "value1" or field == "value2")
            formatted = [f'"{v}"' if isinstance(v, str) else str(v) for v in value]
            return formatted
        else:
            return f'"{value}"'

    def build_condition(self, selections, condition_str):
        # Создание выражения для каждого выбранного фрагмента.
        selection_exprs = {}
        for sel_name, sel_data in selections.items():
            if not isinstance(sel_data, dict):
                continue
            conditions = []
            for field, value in sel_data.items():
                mapped_field = self.map_field(field)
                if isinstance(value, list):
                    # Условие ИЛИ для списка значений
                    formatted_values = self.format_value(value)
                    or_parts = [f'{mapped_field} == {v}' for v in formatted_values]
                    conditions.append(f'({" or ".join(or_parts)})')
                elif value is None:
                    conditions.append(f'{mapped_field} == null')
                else:
                    formatted_value = self.format_value(value)
                    conditions.append(f'{mapped_field} == {formatted_value}')
            selection_exprs[sel_name] = " and ".join(conditions)

        result_condition = condition_str
        for sel_name, expr in selection_exprs.items():
            # Обработка ключевых слов
            if expr:
                result_condition = result_condition.replace(sel_name, f'({expr})')
            else:
                result_condition = result_condition.replace(sel_name, 'true')

        result_condition = result_condition.replace(' and ', ' && ')
        result_condition = result_condition.replace(' or ', ' || ')
        result_condition = result_condition.replace('not ', '!')

        return result_condition

    def extract_mitre_tactics(self, tags):
        if not tags:
            return []
        tactics = []
        for tag in tags:
            if tag.startswith('attack.'):
                tactic = tag.replace('attack.', '')
                if tactic in self.tactic_mapping:
                    tactics.append(tactic)
        return tactics

    def determine_importance(self, rule):
        level_map = {
            "informational": "info",
            "low": "low",
            "medium": "medium",
            "high": "high",
            "critical": "high"
        }

        sigma_level = rule.get('level', 'medium').lower()
        importance = level_map.get(sigma_level, 'medium')

        tags = rule.get('tags', [])
        tactics = self.extract_mitre_tactics(tags)
        for tactic in tactics:
            tactic_importance = self.tactic_mapping.get(tactic, 'medium')
            if tactic_importance == 'high':
                importance = 'high'
                break

        return importance

    def generate_event_directive(self, rule):
        title = rule.get('title', 'Unnamed Rule')
        logsource = rule.get('logsource', {})
        category = logsource.get('category', '')
        product = logsource.get('product', '')

        # Название события сборки
        event_name = f"Sigma_{title.replace(' ', '_').replace('-', '_')[:50]}"

        condition = self.build_condition(
            rule.get('detection', {}),
            rule.get('detection', {}).get('condition', '')
        )

        return f"""event {event_name}:
key:
filter {{{condition}}}"""

    def generate_emit_directive(self, rule):
        title = rule.get('title', 'Unnamed Rule')
        description = rule.get('description', '')
        sigma_id = rule.get('id', str(uuid.uuid4()))
        references = rule.get('references', [])
        tags = rule.get('tags', [])

        importance = self.determine_importance(rule)

        mitre_techniques = [t.replace('attack.', '') for t in tags if t.startswith('attack.t')]

        refs_str = ', '.join([f'"{r}"' for r in references[:3]]) if references else '""'
        tags_str = ', '.join([f'"{t}"' for t in tags[:5]]) if tags else '""'
        mitre_str = ', '.join([f'"{t}"' for t in mitre_techniques[:5]]) if mitre_techniques else '""'

        return f"""emit {{
    $correlation_type = "event"
    $importance = "{importance}"
    $object = "process"
    $action = "execute"
    $status = "success"
    $subject = "account"
    $datafield1 = "{title}"
    $datafield2 = "{description[:100] if description else ''}"
    $datafield3 = "{sigma_id}"
    $datafield4 = {refs_str}
    $datafield5 = {tags_str}
    $datafield6 = {mitre_str}
}}"""

    def convert(self, sigma_file_path, output_path=None):
        rule = self.load_sigma_rule(sigma_file_path)

        title = rule.get('title', 'Unnamed_Rule')
        rule_name = f"Sigma_{title.replace(' ', '_').replace('-', '_')}"

        event_directive = self.generate_event_directive(rule)
        emit_directive = self.generate_emit_directive(rule)

        maxpatrol_rule = f"""# Converted from Sigma rule: {title}
# Original Sigma ID: {rule.get('id', 'N/A')}
# Description: {rule.get('description', '')}
# Author: {rule.get('author', '')}
# MITRE ATT&CK: {', '.join([t for t in rule.get('tags', []) if t.startswith('attack.')])}

{event_directive}

rule {rule_name}: {rule_name}

{emit_directive}
"""

        if output_path:
            os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(maxpatrol_rule)
            print(f"Rule saved to: {output_path}")

        return maxpatrol_rule

def main():
    parser = argparse.ArgumentParser(
        description='Convert Sigma detection rules to MaxPatrol SIEM correlation rules'
    )
    parser.add_argument(
        'input',
        help='Path to Sigma rule file (YAML)'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output file path (optional). If not specified, prints to stdout.'
    )

    args = parser.parse_args()

    converter = SigmaToMaxPatrolConverter()
    result = converter.convert(args.input, args.output)

    if not args.output:
        print(result)

if __name__ == '__main__':
    main()