import os

from ai_asset_obfuscate.vision_api.image_data_asset_obfuscation import ImageDataAssetObfuscation
from ai_asset_obfuscate.vision_api.video_data_asset_obfuscation import VideoDataAssetObfuscation
from ai_asset_obfuscate.api.data_asset_obfuscation import DataAssetObfuscation
from ai_asset_obfuscate.exception import ObfException

# 设置 DSC 环境变量（故意设置错误的环境变量来测试拦截）


# 使用更长的种子内容（至少 32 字符）
seed = "a" * 64

# 测试 ImageDataAssetObfuscation
print("Testing ImageDataAssetObfuscation...")
try:
  img_obf = ImageDataAssetObfuscation()
  result = img_obf.set_seed_content(seed_content=seed)
  print(f"Result: {result}")
except ObfException as e:
  print(f"✓ 拦截成功: {e.code} - {e.message}")

# 测试 VideoDataAssetObfuscation
print("\nTesting VideoDataAssetObfuscation...")
try:
  video_obf = VideoDataAssetObfuscation()
  result = video_obf.set_seed_content(seed_content=seed)
  print(f"Result: {result}")
except ObfException as e:
  print(f"✓ 拦截成功: {e.code} - {e.message}")

# 测试 DataAssetObfuscation（文本数据混淆）
print("\nTesting DataAssetObfuscation...")
try:
  data_obf = DataAssetObfuscation(vocab_size=32000)
  result = data_obf.set_seed_content(seed_content=seed)
  print(f"Result: {result}")
except ObfException as e:
  print(f"✓ 拦截成功: {e.code} - {e.message}")