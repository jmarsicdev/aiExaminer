import pytsk3
import binascii

image_path = "/tmp/raw_image/ewf1"
offset = 63 * 512

try:
    img = pytsk3.Img_Info(image_path)
    data = img.read(offset, 512)
    print(f"--- HEX DUMP at Offset {offset} (Sector 63) ---")
    print(binascii.hexlify(data[:64], sep=' ').decode())
    if b"NTFS" in data:
        print("Found NTFS string in sector 63.")
    else:
        print("NTFS string NOT found in sector 63.")
        
except Exception as e:
    print(f"Error: {e}")
