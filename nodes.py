import requests
import base64
import time
import json
import zlib
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class QwenSecureE2EEClient:
    """
    [Z-Engineer E2EE 클라이언트 - 자동 세션 관리 버전]
    - 최적화: zlib 압축으로 전송량 절감 및 세션 키 재사용으로 속도 향상
    - 지능형 리셋: 서버 재시작으로 인한 공개키 변경 시 세션 자동 초기화
    - 보안: ECC(P-256) 기반 핸드셰이크 및 AES-256-GCM 암호화
    """
    
    # 클래스 수준에서 세션 정보 유지
    _shared_key = None
    _client_pub_b64 = None
    _last_key_time = 0
    _key_lifetime = 3600 
    _current_server_pub_key = "" # 현재 세션에 연결된 서버 공개키 추적용
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
            "4. Do NOT use double quotes at the start and end of the output.\n"
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
            session.mount('http://', adapter)
            cls._session = session
        return cls._session

    def send_request(self, api_url, api_key, server_pub_key, system_prompt, prompt, seed, max_tokens, temperature, timeout):
        api_url = api_url.strip().rstrip("/")
        api_key = api_key.strip()
        server_pub_key = server_pub_key.strip()
        current_time = time.time()

        # [중요] 서버 공개키가 변경되었는지 확인 (서버 재시작 대응)
        if self._current_server_pub_key != server_pub_key:
            print(f"🔄 [Z-Engineer] 서버 키 변경 감지 (또는 최초 연결). 세션을 초기화합니다.")
            QwenSecureE2EEClient._shared_key = None
            QwenSecureE2EEClient._current_server_pub_key = server_pub_key

        try:
            # 1. 세션 키가 없거나 만료된 경우 Handshake 수행
            if (self._shared_key is None or 
                current_time - self._last_key_time > self._key_lifetime):
                
                print("🔐 [Z-Engineer] 보안 핸드셰이크를 시작합니다...")
                client_key = ECC.generate(curve='P-256')
                client_pub_raw = client_key.public_key().export_key(format='raw')
                self._client_pub_b64 = base64.b64encode(client_pub_raw).decode('utf-8')
                
                # 서버 키 로드
                s_pub_raw = base64.b64decode(server_pub_key)
                server_pub = ECC.import_key(s_pub_raw, curve_name='P-256')
                
                # Shared Secret 유도 (.pointQ 사용)
                shared_point = client_key.d * server_pub.pointQ
                self._shared_key = SHA256.new(int(shared_point.x).to_bytes(32, 'big')).digest()
                self._last_key_time = current_time
                print("✅ [Z-Engineer] 보안 세션이 확립되었습니다.")

            # 2. 데이터 패키징 및 zlib 압축
            payload_json = json.dumps({
                "system_prompt": system_prompt,
                "prompt": prompt,
                "seed": seed,
                "max_tokens": max_tokens,
                "temperature": temperature
            })
            compressed_payload = zlib.compress(payload_json.encode('utf-8'), level=9)
            
            # 3. AES-256-GCM 암호화
            cipher_enc = AES.new(self._shared_key, AES.MODE_GCM)
            ciphertext, tag = cipher_enc.encrypt_and_digest(compressed_payload)
            
            # nonce(16) + tag(16) + ciphertext 결합
            combined_data = cipher_enc.nonce + tag + ciphertext
            encrypted_payload = base64.b64encode(combined_data).decode('utf-8')

            # 4. 서버 전송
            response = self._get_session().post(
                f"{api_url}/engineer_secure",
                json={"client_pub": self._client_pub_b64, "data": encrypted_payload},
                headers={"X-API-Key": api_key},
                timeout=timeout
            )

            if response.status_code == 200:
                # 5. 복호화 및 압축 해제
                res_data = base64.b64decode(response.json()['result'])
                nonce, tag, ciphertext = res_data[:16], res_data[16:32], res_data[32:]
                
                cipher_dec = AES.new(self._shared_key, AES.MODE_GCM, nonce=nonce)
                decrypted_compressed = cipher_dec.decrypt_and_verify(ciphertext, tag)
                final_text = zlib.decompress(decrypted_compressed).decode('utf-8')
                
                return (final_text.strip(),)
            
            else:
                # 오류 발생 시 세션 키 무효화 (다음 실행 시 재시도 유도)
                QwenSecureE2EEClient._shared_key = None
                return (f"❌ 서버 응답 에러 ({response.status_code}): {response.text[:100]}",)

        except Exception as e:
            # 통신 에러나 MAC 검증 실패 시 키 초기화
            QwenSecureE2EEClient._shared_key = None
            return (f"❌ 보안 통신 에러: {str(e)}",)

    @classmethod
    def IS_CHANGED(cls, **kwargs):
        return float("nan")

NODE_CLASS_MAPPINGS = {"QwenSecureE2EEClient": QwenSecureE2EEClient}
NODE_DISPLAY_NAME_MAPPINGS = {"QwenSecureE2EEClient": "Z-Engineer Client (E2EE + zlib)"}
