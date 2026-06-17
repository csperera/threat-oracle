# add this to test_gemini.py and rerun
import os
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

for m in genai.list_models():
    if "flash" in m.name.lower() or "pro" in m.name.lower():
        print(m.name, m.supported_generation_methods)