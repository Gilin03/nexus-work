# NEXUS 포트폴리오 (공개용 정적 페이지)

`index.html` + `screenshots/` 로 이뤄진 정적 사이트입니다. 빌드 과정이 없습니다.
직원 이름, IP 주소, 호스트명은 화면 캡처와 본문에서 가려 두었습니다(본인 이름은 작성자 표기로 남김).

## Vercel 배포
1. Vercel 에서 이 저장소를 Import 합니다.
2. **Root Directory** 를 `portfolio` 로 지정합니다(Framework Preset: Other, 빌드 명령 없음).
3. 또는 CLI: `cd portfolio && vercel --prod`

## 참고
- `vercel.json` 에 `noindex` 헤더가 있습니다. 검색에 노출하려면 `X-Robots-Tag` 항목을 지우세요.
- 캡처를 새로 찍을 때는 직원 이름·IP 가 그대로 나오므로 같은 방식으로 가린 뒤 올리세요.
