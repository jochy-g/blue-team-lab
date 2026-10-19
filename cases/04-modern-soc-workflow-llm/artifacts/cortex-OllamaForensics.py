```
#!/usr/bin/env python3
# encoding: utf-8

import json
import requests
from cortexutils.analyzer import Analyzer


class OllamaForensicsAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.ollama_url = self.get_param('config.ollama_url', 'http://172.18.0.1:11434')
        self.model = self.get_param('config.model', 'phi3:mini')

    def summary(self, raw):
        taxonomies = []
        verdict = raw.get('verdict', 'info').lower()
        level_map = {
            'safe': 'safe',
            'suspicious': 'suspicious',
            'malicious': 'malicious',
            'info': 'info'
        }
        level = level_map.get(verdict, 'info')
        taxonomies.append(
            self.build_taxonomy(level, 'OllamaLLM', 'Verdict', verdict.upper())
        )
        return {"taxonomies": taxonomies}

    def run(self):
        observable = self.get_data()
        data_type = self.data_type

        prompt = f"""You are a SOC Tier-2 analyst. Analyze this {data_type}: {observable}

Provide a forensic triage in strict JSON format with these fields:
- verdict: one of "safe", "suspicious", "malicious", "info"
- confidence: integer 0-100
- reasoning: 2-3 sentences explaining your assessment
- recommended_actions: list of 2-3 concrete next steps for the SOC analyst
- iocs_to_pivot: list of related IOCs or indicators to search for

Respond ONLY with valid JSON, no markdown, no explanation outside the JSON."""

        try:
            response = requests.post(
                f"{self.ollama_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json"
                },
                timeout=180
            )
            response.raise_for_status()
            result = response.json()
            llm_output = result.get('response', '{}')

            try:
                parsed = json.loads(llm_output)
            except json.JSONDecodeError:
                parsed = {
                    "verdict": "info",
                    "confidence": 0,
                    "reasoning": "LLM did not return valid JSON",
                    "raw_response": llm_output
                }

            parsed['model'] = self.model
            parsed['observable'] = observable
            parsed['data_type'] = data_type

            self.report(parsed)

        except requests.exceptions.RequestException as e:
            self.error(f"Ollama API error: {str(e)}")
        except Exception as e:
            self.error(f"Analyzer error: {str(e)}")


if __name__ == '__main__':
    OllamaForensicsAnalyzer().run()

```
