# NEXUS 포트폴리오 (정적 페이지)

`index.html` + `screenshots/` 로 이뤄진 정적 사이트입니다. 빌드 과정이 없습니다.

## Vercel 배포
1. Vercel 에서 이 저장소를 Import 합니다.
2. **Root Directory** 를 `portfolio` 로 지정합니다(Framework Preset: Other, 빌드 명령 없음).
3. 또는 CLI: `cd portfolio && vercel --prod`

## 공개 전 확인
- 캡처에 팀원 실명·내부 IP(192.168.3.x)가 보입니다. 외부 공개용이면 가리거나 Vercel 의 Deployment Protection 을 켜세요.
- `vercel.json` 에 `noindex` 헤더를 넣어 검색 노출을 막아 두었습니다.
