import pytsk3
import binascii

image_path = "/home/jmarsic/Downloads/GP2024.E01"

try:
    print("Attempting to force TSK_IMG_TYPE_EWF_EWF...")
    img = pytsk3.Img_Info(image_path, pytsk3.TSK_IMG_TYPE_EWF_EWF)
    data = img.read(0, 1024)
    print("--- HEX DUMP (First 1024 bytes) ---")
    print(binascii.hexlify(data, sep=' ', bytes_per_sep=16).decode('utf-8'))
except Exception as e:
    print(f"Error forcing EWF: {e}")
