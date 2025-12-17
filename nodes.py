import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlparse
import time

class QwenSimpleClient:
    """
    [Z-Engineer 최종 클라이언트]
    - 보안: API Key 인증 및 HTTPS 통신 최적화
    - 성능: 세션 타임아웃 및 Keep-Alive 기반 HTTP/2 대응
    - 안정성: 지수 백오프 재시도 로직 및 상세 에러 핸들링
    """
    
    _session = None
    _session_created_at = None
    SESSION_LIFETIME = 3600  # 1시간마다 세션 갱신

    @classmethod
    def INPUT_TYPES(s):
        return {
            "required": {
                "api_url": ("STRING", {
                    "default": "", 
                    "multiline": False, 
                    "tooltip": "서버 실행 후 생성된 Cloudflare 주소 (https://...)"
                }),
                "api_key": ("STRING", {
                    "default": "", 
                    "multiline": False, 
                    "tooltip": "서버 로그에 출력된 32자 16진수 보안 키"
                }),
                "prompt": ("STRING", {
                    "default": "a photo of cat", 
                    "multiline": True,
                    "tooltip": "확장할 기본 프롬프트"
                }),
                "seed": ("INT", {"default": 0, "min": 0, "max": 0xffffffffffffffff}),
                "max_tokens": ("INT", {
                    "default": 512, 
                    "min": 64, 
                    "max": 4096, 
                    "tooltip": "생성될 문장의 최대 길이"
                }),
                "temperature": ("FLOAT", {
                    "default": 0.7, 
                    "min": 0.0, 
                    "max": 1.0, 
                    "step": 0.01, 
                    "tooltip": "창의성 수치 (높을수록 화려한 묘사)"
                }),
                "timeout": ("INT", {
                    "default": 60,
                    "min": 10,
                    "max": 300,
                    "tooltip": "응답 대기 시간(초)"
                }),
            }
        }

    RETURN_TYPES = ("STRING",)
    RETURN_NAMES = ("text",)
    FUNCTION = "send_request"
    CATEGORY = "QwenTextEngineer"

    @classmethod
    def _get_session(cls):
        current_time = time.time()
        if (cls._session is None or 
            cls._session_created_at is None or 
            current_time - cls._session_created_at > cls.SESSION_LIFETIME):
            
            if cls._session:
                cls._session.close()
            
            session = requests.Session()
            # HTTP/2 환경에서의 안정성을 위한 재시도 설정
            retries = Retry(
                total=3,
                backoff_factor=0.3,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["POST"]
            )
            adapter = HTTPAdapter(max_retries=retries, pool_connections=10, pool_maxsize=10)
            session.mount('https://', adapter)
            session.mount('http://', adapter)
            
            cls._session = session
            cls._session_created_at = current_time
            print("[Qwen Client] 세션 최적화 완료 (Keep-Alive 활성화)")
        
        return cls._session

    def send_request(self, api_url, api_key, prompt, seed, max_tokens, temperature, timeout):
        # 1. 입력값 정제
        api_url = api_url.strip().rstrip("/")
        api_key = api_key.strip()

        if not api_url or not api_key:
            return ("❌ URL과 API Key를 입력해야 합니다.",)

        # 2. 요청 엔드포인트 및 헤더 구성
        # /docs 접속 차단 설정을 서버에 했으므로 /engineer 경로만 사용
        endpoint = f"{api_url}/engineer"
        headers = {
            "Content-Type": "application/json",
            "X-API-Key": api_key,
            "User-Agent": "ComfyUI-Z-Engineer-Client/1.1",
            "Accept": "application/json"
        }

        payload = {
            "prompt": prompt,
            "seed": seed,
            "max_tokens": max_tokens,
            "temperature": temperature
        }

        session = self._get_session()

        try:
            # 3. 데이터 전송
            response = session.post(endpoint, json=payload, headers=headers, timeout=timeout)
            
            if response.status_code == 200:
                result = response.json()
                final_text = result.get('result', '').strip()
                if not final_text:
                    return ("⚠️ 서버 응답이 비어있습니다.",)
                return (final_text,)
            
            elif response.status_code == 403:
                return ("⛔ 보안 에러: API Key가 올바르지 않습니다.",)
            elif response.status_code == 404:
                return ("❌ 서버 오류: 경로를 찾을 수 없습니다. (404 Not Found)",)
            else:
                return (f"❌ 서버 응답 오류 ({response.status_code}): {response.text[:100]}",)
                
        except requests.exceptions.Timeout:
            return (f"⏱️ 타임아웃: 서버가 {timeout}초 내에 응답하지 않았습니다.",)
        except requests.exceptions.ConnectionError:
            QwenSimpleClient._session = None # 연결 오류 시 세션 강제 초기화
            return ("🔌 연결 실패: 서버 주소가 정확한지, 서버가 켜져 있는지 확인하세요.",)
        except Exception as e:
            return (f"❌ 예상치 못한 오류: {str(e)}",)

    @classmethod
    def IS_CHANGED(cls, **kwargs):
        # 매 실행마다 새로운 결과를 얻기 위해 캐싱 방지
        return float("nan")

NODE_CLASS_MAPPINGS = {
    "QwenSimpleClient": QwenSimpleClient
}

NODE_DISPLAY_NAME_MAPPINGS = {
    "QwenSimpleClient": "Z-Engineer Client (Simple)"
}