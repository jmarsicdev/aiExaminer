import pytsk3
import binascii

image_path = "/tmp/raw_image/ewf1"

try:
    img = pytsk3.Img_Info(image_path)
    # Check sector 1 (offset 512) for GPT header
    data = img.read(512, 512)
    print("--- Sector 1 Hex Dump ---")
    print(binascii.hexlify(data[:64], sep=' ').decode())
    if b"EFI PART" in data:
        print("FOUND GPT HEADER!")
except Exception as e:
    print(f"Error: {e}")
