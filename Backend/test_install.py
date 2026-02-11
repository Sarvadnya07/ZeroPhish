import sys

print("=== Python Environment Test ===")
print(f"Python version: {sys.version}")
print()

# Test imports
modules_to_test = [
    "fastapi",
    "uvicorn", 
    "whois",
    "google.generativeai",
    "pydantic",
    "redis",
    "dotenv"
]

for module_name in modules_to_test:
    try:
        __import__(module_name)
        print(f"✅ {module_name}: OK")
    except ImportError as e:
        print(f"❌ {module_name}: NOT FOUND")
        print(f"   Error: {e}")

print()
print("=== Test Complete ===")