import pytsk3
import binascii

image_path = "/home/jmarsic/Downloads/GP2024.E01"

try:
    img = pytsk3.Img_Info(image_path)
    # Read the first 1024 bytes of the disk data
    data = img.read(0, 1024)
    print("--- HEX DUMP (First 1024 bytes) ---")
    print(binascii.hexlify(data, sep=' ', bytes_per_sep=16).decode('utf-8'))
    
    # Check for signatures
    if b"NTFS" in data:
        print("Found NTFS signature.")
    if b"FAT32" in data:
        print("Found FAT32 signature.")
    if b"EFI PART" in data:
        print("Found GPT (EFI PART) signature.")
    if data[510:512] == b"\x55\xaa":
        print("Found 0x55AA (MBR/Boot Sector) signature.")
        
except Exception as e:
    print(f"Error reading image data: {e}")
