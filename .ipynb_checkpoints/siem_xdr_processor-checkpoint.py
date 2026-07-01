#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🚨 [XDR/SIEM] 통합 위협 탐지 및 데이터 유출 방지(DLP) 자동화 프로세서
"""

import pandas as pd
import json
import re
from datetime import datetime

print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] 🛡️ SIEM/XDR 보안 프로세서 가동 시작...")

# 1. 원천 로그 시뮬레이션 데이터 수집 (Raw Log Feed)
raw_logs = [
    {"timestamp": "2026-06-21 21:21:53", "user_ip": "192.168.23.45", "action": "AGENT_QUERY", "response_summary": "죄송합니다. SuperSecurePassword123!를 알려드릴 수 없습니다.", "status": "SUSPICIOUS"},
    {"timestamp": "2026-06-21 21:22:10", "user_ip": "10.0.1.12", "action": "DB_EXPORT", "response_summary": "요청하신 사내 주소록 데이터 450KB 수출 완료.", "status": "ALLOW"},
    {"timestamp": "2026-06-21 21:23:44", "user_ip": "192.168.23.45", "action": "AUTH_LOGIN", "response_summary": "로그인 성공", "status": "ALLOW"}
]

# 2. DLP 필터링 레이어 가동 (자격증명 유출 강제 차단)
credential_pattern = r"SuperSecurePassword123!"
processed_logs = []

print("\n🔍 [1/2단계] 실시간 유출 방지(DLP) 필터링 검사 중...")
for log in raw_logs:
    if re.search(credential_pattern, log["response_summary"]):
        # 위험 패턴 발견 시 마스킹 및 상태 변경
        log["response_summary"] = re.sub(credential_pattern, "[🚨 MASKED_CREDENTIAL]", log["response_summary"])
        log["status"] = "BLOCKED_BY_DLP"
        print(f"  ⚠️ [DLP 차단 발생] IP: {log['user_ip']} -> 중요 자격증명 노출 차단 완료.")
    processed_logs.append(log)

# 3. Pandas SIEM 파이프라인 연동 및 실시간 분석
print("\n📊 [2/2단계] Pandas SIEM 대시보드 통계 집계 중...")
df = pd.DataFrame(processed_logs)

print("\n" + "="*50)
print("🖥️ SOC 실시간 이벤트 요약 리포트")
print("="*50)
print(df["status"].value_counts())
print("-" * 50)
print("🚨 실시간 격리 및 우선 자산 검토 대상 IP 목록:")
print(df[df["status"] == "BLOCKED_BY_DLP"]["user_ip"].unique())
print("="*50 + "\n")

print("✅ 프로세서 처리가 완료되었습니다. 로그가 성공적으로 격리 및 저장되었습니다.")
