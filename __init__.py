
"""
Z-Engineer ComfyUI Node
프롬프트 엔지니어링을 위한 원격 LLM 클라이언트
"""

from .client_node import QwenSimpleClient, NODE_CLASS_MAPPINGS, NODE_DISPLAY_NAME_MAPPINGS

# ComfyUI가 인식할 수 있도록 노드 매핑을 최상위로 노출
__all__ = [
    "NODE_CLASS_MAPPINGS",
    "NODE_DISPLAY_NAME_MAPPINGS",
]

# 버전 정보 (선택사항)
__version__ = "1.0.0"
__author__ = "YTOAA"

# 노드 정보 출력 (디버깅용, 선택사항)
print(f"✅ [Z-Engineer] 노드 로드 완료 (v{__version__})")
print(f"   등록된 노드: {list(NODE_CLASS_MAPPINGS.keys())}")