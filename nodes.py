import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlparse
import time

class QwenSimpleClient:
    """
    [Z-Engineer 클라이언트]
    - 기능: 원격 Colab 서버(HTTP/2)에 프롬프트 확장을 요청
    - 특징: 복잡한 설정 제외, 오직 생성 파라미터만 조작
    - 보안: API Key 인증 적용
    - 성능: Session Keep-Alive 적용
    """
    
    # 세션 재사용을 위한 클래스 변수
    _session = None
    _session_created_at = None
    SESSION_LIFETIME = 3600  # 1시간마다 세션 갱신

    @classmethod
    def INPUT_TYPES(s):
        return {
            "required": {
                # 1. 서버 접속 정보
                "api_url": ("STRING", {
                    "default": "", 
                    "multiline": False, 
                    "tooltip": "서버 실행 후 나온 Cloudflare 주소 (예: https://...trycloudflare.com)"
                }),
                "api_key": ("STRING", {
                    "default": "", 
                    "multiline": False, 
                    "tooltip": "서버 실행 로그에 출력된 32자 인증키 (주의: 워크플로우 공유 시 노출됨)"
                }),
                
                # 2. 프롬프트 입력
                "prompt": ("STRING", {
                    "default": "a photo of cat", 
                    "multiline": True,
                    "tooltip": "확장하고 싶은 간단한 프롬프트를 입력하세요 (권장: 500자 이내)"
                }),
                "seed": ("INT", {"default": 0, "min": 0, "max": 0xffffffffffffffff}),
                
                # 3. 생성 옵션
                "max_tokens": ("INT", {
                    "default": 512, 
                    "min": 64, 
                    "max": 4096, 
                    "tooltip": "생성될 문장의 최대 길이 (길게 쓰고 싶으면 늘리세요)"
                }),
                "temperature": ("FLOAT", {
                    "default": 0.7, 
                    "min": 0.0, 
                    "max": 1.0, 
                    "step": 0.01, 
                    "tooltip": "창의성 조절 (높을수록 다양하고 화려한 묘사)"
                }),
                
                # 4. 고급 옵션
                "timeout": ("INT", {
                    "default": 60,
                    "min": 10,
                    "max": 300,
                    "tooltip": "서버 응답 대기 시간 (초)"
                }),
            }
        }

    RETURN_TYPES = ("STRING",)
    RETURN_NAMES = ("text",)
    FUNCTION = "send_request"
    CATEGORY = "QwenTextEngineer"

    @classmethod
    def _get_session(cls):
        """세션을 가져오거나 생성합니다. 오래된 세션은 갱신합니다."""
        current_time = time.time()
        
        # 세션이 없거나 너무 오래된 경우 새로 생성
        if (cls._session is None or 
            cls._session_created_at is None or 
            current_time - cls._session_created_at > cls.SESSION_LIFETIME):
            
            if cls._session:
                cls._session.close()
            
            session = requests.Session()
            # 재시도 로직: 3회, 지수 백오프
            retries = Retry(
                total=3,
                backoff_factor=0.3,
                status_forcelist=[500, 502, 503, 504],
                allowed_methods=["POST"]
            )
            session.mount('https://', HTTPAdapter(max_retries=retries))
            session.mount('http://', HTTPAdapter(max_retries=retries))
            
            cls._session = session
            cls._session_created_at = current_time
            print("[Qwen Client] 새로운 세션 생성")
        
        return cls._session

    @classmethod
    def _validate_url(cls, url):
        """URL 형식을 검증합니다."""
        try:
            result = urlparse(url)
            if not all([result.scheme, result.netloc]):
                return False
            if result.scheme not in ['http', 'https']:
                return False
            return True
        except Exception:
            return False

    def send_request(self, api_url, api_key, prompt, seed, max_tokens, temperature, timeout):
        # 1. 입력값 정리 및 검증
        api_url = api_url.strip().rstrip("/")
        api_key = api_key.strip()

        # 필수 입력 확인
        if not api_url or not api_key:
            return ("❌ Error: 'api_url'과 'api_key'를 모두 입력해주세요.",)

        # URL 형식 검증
        if not self._validate_url(api_url):
            return ("❌ Error: 올바른 URL 형식이 아닙니다. (예: https://...trycloudflare.com)",)

        # API Key 길이 확인 (32자 hex = 64자)
        if len(api_key) != 32:
            print(f"⚠️ Warning: API Key 길이가 비정상입니다 (현재: {len(api_key)}자, 예상: 32자)")

        # 프롬프트 길이 경고
        if len(prompt) > 1000:
            print(f"⚠️ Warning: 프롬프트가 너무 깁니다 ({len(prompt)}자). 서버에서 잘릴 수 있습니다.")

        # 2. 요청 구성
        endpoint = f"{api_url}/engineer"
        headers = {
            "Content-Type": "application/json",
            "X-API-Key": api_key,
            "Connection": "keep-alive",
            "User-Agent": "ComfyUI-QwenClient/1.0"
        }

        payload = {
            "prompt": prompt,
            "seed": seed,
            "max_tokens": max_tokens,
            "temperature": temperature
        }

        print(f"[Qwen Client] 요청 전송 → {endpoint}")
        print(f"[Qwen Client] 파라미터: Max={max_tokens}, Temp={temperature}, Seed={seed}")

        # 3. 요청 전송
        session = self._get_session()

        try:
            response = session.post(
                endpoint, 
                json=payload, 
                headers=headers, 
                timeout=timeout
            )
            
            # 4. 응답 처리
            if response.status_code == 200:
                try:
                    result = response.json()
                    final_text = result.get('result', '')
                    
                    if not final_text:
                        return ("⚠️ Warning: 서버가 빈 응답을 반환했습니다.",)
                    
                    print(f"[Qwen Client] ✅ 성공! ({len(final_text)}자 생성)")
                    return (final_text,)
                    
                except ValueError as e:
                    return (f"❌ Error: 서버 응답을 파싱할 수 없습니다. {e}",)
            
            elif response.status_code == 403:
                return ("⛔ Error 403: 인증 실패! API Key를 확인하세요.",)
            
            elif response.status_code == 404:
                return ("❌ Error 404: 엔드포인트를 찾을 수 없습니다. URL이 정확한가요?",)
            
            elif response.status_code == 500:
                return (f"❌ Error 500: 서버 내부 오류. 상세: {response.text[:200]}",)
            
            else:
                return (f"❌ Server Error {response.status_code}: {response.text[:200]}",)
                
        except requests.exceptions.Timeout:
            print(f"⏱️ Timeout: 서버가 {timeout}초 내에 응답하지 않았습니다.")
            return (f"❌ Timeout Error: 서버가 {timeout}초 내에 응답하지 않았습니다.",)
        
        except requests.exceptions.ConnectionError as e:
            print(f"🔌 연결 오류: {e}")
            # 연결 오류 시에만 세션 초기화
            QwenSimpleClient._session = None
            QwenSimpleClient._session_created_at = None
            return (f"❌ Connection Error: 서버에 연결할 수 없습니다. URL과 네트워크를 확인하세요.",)
        
        except requests.exceptions.RequestException as e:
            print(f"⚠️ 요청 오류: {e}")
            return (f"❌ Request Error: {str(e)[:200]}",)
        
        except Exception as e:
            print(f"❌ 예상치 못한 오류: {e}")
            return (f"❌ Unexpected Error: {str(e)[:200]}",)

    @classmethod
    def IS_CHANGED(cls, **kwargs):
        """입력이 변경될 때마다 노드를 재실행합니다."""
        # seed나 prompt가 변경되면 재실행
        return float("nan")

# ComfyUI 노드 등록
NODE_CLASS_MAPPINGS = {
    "QwenSimpleClient": QwenSimpleClient
}

NODE_DISPLAY_NAME_MAPPINGS = {
    "QwenSimpleClient": "Z-Engineer Client (Simple)"
}