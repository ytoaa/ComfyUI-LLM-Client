import requests
import base64
import time
import json
import zlib  # 압축 라이브4러리 추가
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class QwenSecureE2EEClient:
    _shared_key = None
    _client_pub_b64 = None
    _last_key_time = 0
    _key_lifetime = 3600 
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
                "api_url": ("STRING", {"default": ""}),
                "api_key": ("STRING", {"default": ""}),
                "server_pub_key": ("STRING", {"default": "", "multiline": True}),
                "system_prompt": ("STRING", {"default": ORIGINAL_SYSTEM_PROMPT, "multiline": True}),
                "prompt": ("STRING", {"default": "a photo of cat", "multiline": True}),
                "seed": ("INT", {"default": 0, "min": 0, "max": 0xffffffffffffffff}),
                "max_tokens": ("INT", {"default": 512, "min": 64, "max": 4096}),
                "temperature": ("FLOAT", {"default": 0.7, "min": 0.0, "max": 1.0, "step": 0.01}),
                "timeout": ("INT", {"default": 60}),
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
            adapter = HTTPAdapter(max_retries=Retry(total=3, backoff_factor=0.3), pool_connections=10, pool_maxsize=10)
            session.mount('https://', adapter)
            cls._session = session
        return cls._session

    def send_request(self, api_url, api_key, server_pub_key, system_prompt, prompt, seed, max_tokens, temperature, timeout):
        api_url, api_key, server_pub_key = api_url.strip().rstrip("/"), api_key.strip(), server_pub_key.strip()
        current_time = time.time()

        try:
            # 1. 세션 키 관리 (Handshake)
            if (self._shared_key is None or current_time - self._last_key_time > self._key_lifetime):
                client_key = ECC.generate(curve='P-256')
                self._client_pub_b64 = base64.b64encode(client_key.public_key().export_key(format='raw')).decode('utf-8')
                server_pub = ECC.import_key(base64.b64decode(server_pub_key), curve_name='P-256')
                shared_point = client_key.d * server_pub.pointQ
                self._shared_key = SHA256.new(int(shared_point.x).to_bytes(32, 'big')).digest()
                self._last_key_time = current_time

            # 2. 데이터 압축 후 암호화 (Compress -> Encrypt)
            payload_json = json.dumps({
                "system_prompt": system_prompt,
                "prompt": prompt,
                "seed": seed,
                "max_tokens": max_tokens,
                "temperature": temperature
            })
            # zlib 압축 적용 (레벨 9)
            compressed_data = zlib.compress(payload_json.encode('utf-8'), level=9)
            
            cipher_enc = AES.new(self._shared_key, AES.MODE_GCM)
            # nonce는 자동으로 생성됨 (16바이트)
            ciphertext, tag = cipher_enc.encrypt_and_digest(compressed_data)
            
            # 중요: nonce(16) + tag(16) + ciphertext 순서로 결합
            combined_data = cipher_enc.nonce + tag + ciphertext
            encrypted_payload = base64.b64encode(combined_data).decode('utf-8')

            # 3. 전송
            response = self._get_session().post(
                f"{api_url}/engineer_secure",
                json={"client_pub": self._client_pub_b64, "data": encrypted_payload},
                headers={"X-API-Key": api_key},
                timeout=timeout
            )

            if response.status_code == 200:
                # 4. 복호화 후 압축 해제 (Decrypt -> Decompress)
                res_data = base64.b64decode(response.json()['result'])
                nonce, tag, ciphertext = res_data[:16], res_data[16:32], res_data[32:]
                cipher_dec = AES.new(self._shared_key, AES.MODE_GCM, nonce=nonce)
                
                decrypted_compressed = cipher_dec.decrypt_and_verify(ciphertext, tag)
                final_text = zlib.decompress(decrypted_compressed).decode('utf-8')
                return (final_text,)
            else:
                QwenSecureE2EEClient._shared_key = None
                return (f"❌ 서버 에러: {response.status_code}",)

        except Exception as e:
            QwenSecureE2EEClient._shared_key = None
            return (f"❌ 보안 통신 에러: {str(e)}",)

NODE_CLASS_MAPPINGS = {"QwenSecureE2EEClient": QwenSecureE2EEClient}
NODE_DISPLAY_NAME_MAPPINGS = {"QwenSecureE2EEClient": "Z-Engineer Client (E2EE + zlib)"}
