import pytsk3
import binascii

image_path = "/home/jmarsic/Downloads/GP2024.E01"

try:
    print("Attempting to open with list [image_path]...")
    img = pytsk3.Img_Info([image_path])
    data = img.read(0, 1024)
    print("--- HEX DUMP (First 16 bytes) ---")
    print(binascii.hexlify(data[:16], sep=' ').decode('utf-8'))
except Exception as e:
    print(f"Error: {e}")
