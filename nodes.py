import requests
import base64
import time
import json
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class QwenSecureE2EEClient:
    """
    [Z-Engineer E2EE 클라이언트 - 세션 최적화 버전]
    - 최적화: 최초 1회 Handshake 후 합의된 키를 메모리에 캐싱하여 속도 극대화
    - 보안: 모든 데이터는 AES-256-GCM 종단 간 암호화 처리
    - 편의: ComfyUI 내에서 시스템 프롬프트 직접 수정 가능
    """
    
    # 세션 유지를 위한 클래스 변수 (메모리에 상주)
    _shared_key = None
    _client_pub_b64 = None
    _last_key_time = 0
    _key_lifetime = 3600  # 1시간 동안 세션 유지
    _session = None

    @classmethod
    def INPUT_TYPES(s):
        ORIGINAL_SYSTEM_PROMPT = (
            "You are Z-Engineer, an expert prompt engineering AI specializing in the Z-Image Turbo architecture (S3-DiT). "
            "Your goal is to rewrite simple user inputs into high-fidelity, \"Positive Constraint\" prompts.\n\n"
            "CORE RULES:\n"
            "1. NO Negative Prompts.\n"
            "2. Use Natural Language Syntax.\n"
            "3. Aggressively describe textures.\n"
            "4. Enclose text in double quotes.\n"
            "5. Explicitly state proper anatomy.\n"
            "6. Always use 'shot on' for camera types.\n\n"
            "OUTPUT FORMAT: Return ONLY the enhanced prompt string."
        )

        return {
            "required": {
                "api_url": ("STRING", {"default": "", "multiline": False}),
                "api_key": ("STRING", {"default": "", "multiline": False}),
                "server_pub_key": ("STRING", {"default": "", "multiline": True}),
                "system_prompt": ("STRING", {"default": ORIGINAL_SYSTEM_PROMPT, "multiline": True}),
                "prompt": ("STRING", {"default": "a photo of cat", "multiline": True}),
                "seed": ("INT", {"default": 0, "min": 0, "max": 0xffffffffffffffff}),
                "max_tokens": ("INT", {"default": 512, "min": 64, "max": 4096}),
                "temperature": ("FLOAT", {"default": 0.7, "min": 0.0, "max": 1.0, "step": 0.01}),
                "timeout": ("INT", {"default": 60, "min": 10, "max": 300}),
            }
        }

    RETURN_TYPES = ("STRING",)
    RETURN_NAMES = ("text",)
    FUNCTION = "send_request"
    CATEGORY = "QwenTextEngineer"

    @classmethod
    def _get_session(cls):
        if cls._session is None:
            session = requests.Session()
            retries = Retry(total=3, backoff_factor=0.3, status_forcelist=[429, 500, 502, 503, 504])
            adapter = HTTPAdapter(max_retries=retries, pool_connections=10, pool_maxsize=10)
            session.mount('https://', adapter)
            session.mount('http://', adapter)
            cls._session = session
        return cls._session

    def send_request(self, api_url, api_key, server_pub_key, system_prompt, prompt, seed, max_tokens, temperature, timeout):
        api_url = api_url.strip().rstrip("/")
        api_key = api_key.strip()
        server_pub_key = server_pub_key.strip()

        if not api_url or not api_key or not server_pub_key:
            return ("❌ 필수 접속 정보를 모두 입력해야 합니다.",)

        current_time = time.time()

        try:
            # 1. 세션 키 관리 (Handshake 생략 로직)
            if (self._shared_key is None or 
                current_time - self._last_key_time > self._key_lifetime):
                
                print("🔐 [Z-Engineer] 보안 세션 키를 생성합니다 (Handshake)...")
                # 클라이언트 임시 ECC 키 생성
                client_key = ECC.generate(curve='P-256')
                client_pub_raw = client_key.public_key().export_key(format='raw')
                self._client_pub_b64 = base64.b64encode(client_pub_raw).decode('utf-8')
                
                # 서버 공개키 로드 및 공유 비밀 유도
                s_pub_raw = base64.b64decode(server_pub_key)
                server_pub = ECC.import_key(s_pub_raw, curve_name='P-256')
                
                # .pointQ 속성 사용 (P-256 호환성)
                shared_point = client_key.d * server_pub.pointQ
                self._shared_key = SHA256.new(int(shared_point.x).to_bytes(32, 'big')).digest()
                self._last_key_time = current_time
            
            # 2. 데이터 암호화 (AES-256-GCM)
            payload_data = json.dumps({
                "system_prompt": system_prompt,
                "prompt": prompt,
                "seed": seed,
                "max_tokens": max_tokens,
                "temperature": temperature
            })
            
            cipher_enc = AES.new(self._shared_key, AES.MODE_GCM)
            ciphertext, tag = cipher_enc.encrypt_and_digest(payload_data.encode('utf-8'))
            encrypted_b64 = base64.b64encode(cipher_enc.nonce + tag + ciphertext).decode('utf-8')

            # 3. 서버 전송
            endpoint = f"{api_url}/engineer_secure"
            headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
            post_data = {
                "client_pub": self._client_pub_b64,
                "data": encrypted_b64
            }
            
            session = self._get_session()
            response = session.post(endpoint, json=post_data, headers=headers, timeout=timeout)
            
            if response.status_code == 200:
                # 4. 서버 응답 복호화
                res_json = response.json()
                enc_res = base64.b64decode(res_json['result'])
                nonce, tag, ciphertext = enc_res[:16], enc_res[16:32], enc_res[32:]
                
                cipher_dec = AES.new(self._shared_key, AES.MODE_GCM, nonce=nonce)
                final_text = cipher_dec.decrypt_and_verify(ciphertext, tag).decode('utf-8')
                return (final_text,)
            
            else:
                # 에러 발생 시 세션 키 초기화 (서버와 키가 어긋났을 가능성 대비)
                QwenSecureE2EEClient._shared_key = None
                return (f"❌ 서버 에러 ({response.status_code}): {response.text[:100]}",)

        except Exception as e:
            QwenSecureE2EEClient._shared_key = None
            return (f"❌ E2EE 보안 통신 에러: {str(e)}",)

    @classmethod
    def IS_CHANGED(cls, **kwargs):
        return float("nan")

NODE_CLASS_MAPPINGS = {"QwenSecureE2EEClient": QwenSecureE2EEClient}
NODE_DISPLAY_NAME_MAPPINGS = {"QwenSecureE2EEClient": "Z-Engineer Client (E2EE Secure)"}