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
    [Z-Engineer E2EE 클라이언트 - 오리지널 프롬프트 복원 버전]
    - 보안: ECC(P-256) + AES-256-GCM 종단 간 암호화 (E2EE)
    - 복원: 기존에 정의된 상세 시스템 프롬프트를 기본값으로 설정
    - 특징: 모든 데이터 전송 시 암호화 및 무결성 검증 수행
    """
    
    _session = None
    _session_created_at = None
    SESSION_LIFETIME = 3600

    @classmethod
    def INPUT_TYPES(s):
        # 기존에 정의했던 상세 시스템 프롬프트 텍스트
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
                "system_prompt": ("STRING", {
                    "default": ORIGINAL_SYSTEM_PROMPT, 
                    "multiline": True
                }),
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
        current_time = time.time()
        if (cls._session is None or 
            cls._session_created_at is None or 
            current_time - cls._session_created_at > cls.SESSION_LIFETIME):
            
            if cls._session: cls._session.close()
            
            session = requests.Session()
            retries = Retry(total=3, backoff_factor=0.3, status_forcelist=[429, 500, 502, 503, 504])
            adapter = HTTPAdapter(max_retries=retries, pool_connections=10, pool_maxsize=10)
            session.mount('https://', adapter)
            session.mount('http://', adapter)
            
            cls._session = session
            cls._session_created_at = current_time
        return cls._session

    def send_request(self, api_url, api_key, server_pub_key, system_prompt, prompt, seed, max_tokens, temperature, timeout):
        api_url = api_url.strip().rstrip("/")
        api_key = api_key.strip()
        server_pub_key = server_pub_key.strip()

        if not api_url or not api_key or not server_pub_key:
            return ("❌ 필수 접속 정보가 누락되었습니다.",)

        try:
            # 1. ECDH 키 합의
            client_key = ECC.generate(curve='P-256')
            client_pub_raw = client_key.public_key().export_key(format='raw')
            
            s_pub_raw = base64.b64decode(server_pub_key)
            server_pub = ECC.import_key(s_pub_raw, curve_name='P-256')
            
            shared_point = client_key.d * server_pub.point
            aes_key = SHA256.new(int(shared_point.x).to_bytes(32, 'big')).digest()

            # 2. 데이터 패키징 및 암호화
            payload_data = json.dumps({
                "system_prompt": system_prompt,
                "prompt": prompt,
                "seed": seed,
                "max_tokens": max_tokens,
                "temperature": temperature
            })
            
            cipher_enc = AES.new(aes_key, AES.MODE_GCM)
            ciphertext, tag = cipher_enc.encrypt_and_digest(payload_data.encode('utf-8'))
            encrypted_b64 = base64.b64encode(cipher_enc.nonce + tag + ciphertext).decode('utf-8')

            # 3. 서버 전송
            endpoint = f"{api_url}/engineer_secure"
            headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
            post_data = {
                "client_pub": base64.b64encode(client_pub_raw).decode('utf-8'),
                "data": encrypted_b64
            }
            
            session = self._get_session()
            response = session.post(endpoint, json=post_data, headers=headers, timeout=timeout)
            
            if response.status_code == 200:
                # 4. 서버 응답 복호화
                res_json = response.json()
                enc_res = base64.b64decode(res_json['result'])
                nonce, tag, ciphertext = enc_res[:16], enc_res[16:32], enc_res[32:]
                
                cipher_dec = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
                final_text = cipher_dec.decrypt_and_verify(ciphertext, tag).decode('utf-8')
                return (final_text,)
            
            elif response.status_code == 403:
                return ("⛔ 인증 실패: API Key를 확인하세요.",)
            else:
                return (f"❌ 서버 오류 ({response.status_code}): {response.text[:100]}",)

        except Exception as e:
            return (f"❌ E2EE 보안 통신 에러: {str(e)}",)

    @classmethod
    def IS_CHANGED(cls, **kwargs):
        return float("nan")

NODE_CLASS_MAPPINGS = {"QwenSecureE2EEClient": QwenSecureE2EEClient}
NODE_DISPLAY_NAME_MAPPINGS = {"QwenSecureE2EEClient": "Z-Engineer Client (E2EE Secure)"}