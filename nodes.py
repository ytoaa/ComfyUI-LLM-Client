import requests
import base64
import time
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class QwenSecureE2EEClient:
    """
    [Z-Engineer E2EE 클라이언트]
    - 보안: ECC(P-256) + AES-256-GCM 종단 간 암호화 (E2EE)
    - 특징: 서버와 클라이언트만 내용을 복호화 가능 (Cloudflare 도청 방지)
    - 안정성: 세션 유지 및 자동 재시도 로직 포함
    """
    
    _session = None
    _session_created_at = None
    SESSION_LIFETIME = 3600

    @classmethod
    def INPUT_TYPES(s):
        return {
            "required": {
                "api_url": ("STRING", {"default": "", "multiline": False}),
                "api_key": ("STRING", {"default": "", "multiline": False}),
                "server_pub_key": ("STRING", {"default": "", "multiline": True}),
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

    def send_request(self, api_url, api_key, server_pub_key, prompt, seed, max_tokens, temperature, timeout):
        # 1. 기본 검증
        api_url = api_url.strip().rstrip("/")
        api_key = api_key.strip()
        server_pub_key = server_pub_key.strip()

        if not api_url or not api_key or not server_pub_key:
            return ("❌ API URL, Key, Server Pub Key를 모두 입력해야 합니다.",)

        try:
            # 2. E2EE 준비: 클라이언트 임시 ECC 키 생성
            client_key = ECC.generate(curve='P-256')
            client_pub_raw = client_key.public_key().export_key(format='raw')
            
            # 3. 서버 공개키 임포트 및 Shared Secret 유도 (ECDH)
            s_pub_raw = base64.b64decode(server_pub_key)
            server_pub = ECC.import_key(s_pub_raw, curve_name='P-256')
            shared_point = client_key.d * server_pub.point
            # Shared Secret으로부터 32바이트 AES 키 생성
            aes_key = SHA256.new(int(shared_point.x).to_bytes(32, 'big')).digest()

            # 4. 요청 데이터 암호화 (AES-256-GCM)
            cipher_enc = AES.new(aes_key, AES.MODE_GCM)
            # 프롬프트 외에 seed, temp 등도 함께 암호화하려면 JSON화
            import json
            payload_data = json.dumps({
                "prompt": prompt,
                "seed": seed,
                "max_tokens": max_tokens,
                "temperature": temperature
            })
            ciphertext, tag = cipher_enc.encrypt_and_digest(payload_data.encode('utf-8'))
            encrypted_b64 = base64.b64encode(cipher_enc.nonce + tag + ciphertext).decode('utf-8')

            # 5. 전송
            endpoint = f"{api_url}/engineer_secure"
            headers = {"X-API-Key": api_key, "Content-Type": "application/json"}
            post_data = {
                "client_pub": base64.b64encode(client_pub_raw).decode('utf-8'),
                "data": encrypted_b64
            }
            
            session = self._get_session()
            response = session.post(endpoint, json=post_data, headers=headers, timeout=timeout)
            
            if response.status_code == 200:
                # 6. 응답 복호화
                res_json = response.json()
                enc_res = base64.b64decode(res_json['result'])
                nonce, tag, ciphertext = enc_res[:16], enc_res[16:32], enc_res[32:]
                
                cipher_dec = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
                final_text = cipher_dec.decrypt_and_verify(ciphertext, tag).decode('utf-8')
                return (final_text,)
            
            elif response.status_code == 403:
                return ("⛔ 보안 에러: API Key가 올바르지 않습니다.",)
            else:
                return (f"❌ 서버 에러 ({response.status_code}): {response.text[:100]}",)

        except Exception as e:
            return (f"❌ E2EE 통신 실패: {str(e)}",)

    @classmethod
    def IS_CHANGED(cls, **kwargs):
        return float("nan")

NODE_CLASS_MAPPINGS = {"QwenSecureE2EEClient": QwenSecureE2EEClient}
NODE_DISPLAY_NAME_MAPPINGS = {"QwenSecureE2EEClient": "Z-Engineer Client (E2EE)"}