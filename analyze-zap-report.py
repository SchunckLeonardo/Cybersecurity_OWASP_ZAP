#!/usr/bin/env python3
"""
Script para análise detalhada do relatório OWASP ZAP
Extrai estatísticas e identifica vulnerabilidades mais comuns
"""

import xml.etree.ElementTree as ET
import json
from collections import Counter
from typing import Dict, List

def parse_zap_report(xml_file: str) -> Dict:
    """
    Analisa o arquivo XML do ZAP e extrai informações de vulnerabilidades
    """
    tree = ET.parse(xml_file)
    root = tree.getroot()

    vulnerabilities = []
    severity_count = Counter()
    vulnerability_types = Counter()

    # Mapeia risk codes para severidades
    risk_map = {
        '0': 'Informativo',
        '1': 'Baixo',
        '2': 'Médio',
        '3': 'Alto',
        '4': 'Crítico'
    }

    # Extrai alertas do relatório
    for site in root.findall('.//site'):
        for alert in site.findall('.//alertitem'):
            alert_name = alert.find('alert').text if alert.find('alert') is not None else 'N/A'
            risk_code = alert.find('riskcode').text if alert.find('riskcode') is not None else '0'
            risk_desc = alert.find('riskdesc').text if alert.find('riskdesc') is not None else 'N/A'
            desc = alert.find('desc').text if alert.find('desc') is not None else 'N/A'
            solution = alert.find('solution').text if alert.find('solution') is not None else 'N/A'
            confidence = alert.find('confidence').text if alert.find('confidence') is not None else 'N/A'

            instances = []
            for instance in alert.findall('.//instance'):
                uri = instance.find('uri').text if instance.find('uri') is not None else 'N/A'
                method = instance.find('method').text if instance.find('method') is not None else 'N/A'
                param = instance.find('param').text if instance.find('param') is not None else 'N/A'

                instances.append({
                    'uri': uri,
                    'method': method,
                    'param': param
                })

            severity = risk_map.get(risk_code, 'Desconhecido')
            severity_count[severity] += 1
            vulnerability_types[alert_name] += 1

            vulnerabilities.append({
                'name': alert_name,
                'severity': severity,
                'risk_code': risk_code,
                'description': desc[:200] + '...' if len(desc) > 200 else desc,
                'solution': solution[:200] + '...' if len(solution) > 200 else solution,
                'confidence': confidence,
                'instances_count': len(instances),
                'instances': instances[:3]  # Limita a 3 instâncias
            })

    return {
        'total_alerts': len(vulnerabilities),
        'severity_breakdown': dict(severity_count),
        'vulnerability_types': dict(vulnerability_types.most_common(10)),
        'vulnerabilities': vulnerabilities
    }

def generate_summary_report(analysis: Dict) -> str:
    """
    Gera um relatório resumido em texto
    """
    report = []
    report.append("=" * 70)
    report.append("RELATÓRIO DE ANÁLISE DE SEGURANÇA - OWASP ZAP")
    report.append("=" * 70)
    report.append("")

    # Resumo geral
    report.append("📊 RESUMO GERAL")
    report.append(f"Total de alertas identificados: {analysis['total_alerts']}")
    report.append("")

    # Alertas por severidade
    report.append("🎯 ALERTAS POR SEVERIDADE")
    report.append("-" * 40)
    severity_order = ['Crítico', 'Alto', 'Médio', 'Baixo', 'Informativo']
    for severity in severity_order:
        count = analysis['severity_breakdown'].get(severity, 0)
        if count > 0:
            emoji = {
                'Crítico': '🔴',
                'Alto': '🟠',
                'Médio': '🟡',
                'Baixo': '🔵',
                'Informativo': '⚪'
            }.get(severity, '⚫')
            report.append(f"{emoji} {severity:15s}: {count:3d} alerta(s)")
    report.append("")

    # Tipos de vulnerabilidades mais comuns
    report.append("🔍 TOP 10 VULNERABILIDADES MAIS COMUNS")
    report.append("-" * 40)
    for i, (vuln_type, count) in enumerate(analysis['vulnerability_types'].items(), 1):
        report.append(f"{i:2d}. {vuln_type:45s}: {count:2d}x")
    report.append("")

    # Detalhes das vulnerabilidades críticas e altas
    critical_high = [v for v in analysis['vulnerabilities']
                     if v['severity'] in ['Crítico', 'Alto']]

    if critical_high:
        report.append("⚠️  VULNERABILIDADES CRÍTICAS E ALTAS - DETALHES")
        report.append("=" * 70)
        for vuln in critical_high:
            report.append(f"\n🚨 {vuln['name']}")
            report.append(f"   Severidade: {vuln['severity']}")
            report.append(f"   Confiança: {vuln['confidence']}")
            report.append(f"   Instâncias encontradas: {vuln['instances_count']}")
            report.append(f"   Descrição: {vuln['description']}")
            report.append(f"   Solução: {vuln['solution']}")
            if vuln['instances']:
                report.append(f"   Exemplo de ocorrência:")
                for inst in vuln['instances'][:1]:
                    report.append(f"      - {inst['method']} {inst['uri']}")
                    if inst['param'] != 'N/A':
                        report.append(f"        Parâmetro: {inst['param']}")
            report.append("-" * 70)

    report.append("")
    report.append("=" * 70)

    # Conclusão
    critical_count = analysis['severity_breakdown'].get('Crítico', 0)
    high_count = analysis['severity_breakdown'].get('Alto', 0)

    if critical_count > 0 or high_count > 0:
        report.append("❌ STATUS: PIPELINE DEVE FALHAR")
        report.append(f"   Motivo: {critical_count} vulnerabilidade(s) crítica(s) ")
        report.append(f"           e {high_count} alta(s) detectada(s)")
    else:
        report.append("✅ STATUS: PIPELINE PODE PROSSEGUIR")
        report.append("   Nenhuma vulnerabilidade crítica ou alta detectada")

    report.append("=" * 70)

    return "\n".join(report)

def main():
    import sys

    if len(sys.argv) < 2:
        print("Uso: python analyze-zap-report.py <arquivo-xml-zap>")
        sys.exit(1)

    xml_file = sys.argv[1]

    try:
        analysis = parse_zap_report(xml_file)

        # Gera relatório em texto
        summary = generate_summary_report(analysis)
        print(summary)

        # Salva análise em JSON
        with open('zap-analysis.json', 'w', encoding='utf-8') as f:
            json.dump(analysis, f, indent=2, ensure_ascii=False)
        print("\n📄 Análise detalhada salva em: zap-analysis.json")

        # Retorna código de erro se houver vulnerabilidades críticas/altas
        critical = analysis['severity_breakdown'].get('Crítico', 0)
        high = analysis['severity_breakdown'].get('Alto', 0)

        if critical > 0 or high > 0:
            sys.exit(1)

    except Exception as e:
        print(f"Erro ao analisar relatório: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()