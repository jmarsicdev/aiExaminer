import pytsk3
import binascii

image_path = "/tmp/raw_image/ewf1"

try:
    print(f"--- Debugging Raw Mounted Image: {image_path} ---")
    img = pytsk3.Img_Info(image_path)
    
    # Check the first 512 bytes (MBR area)
    mbr_data = img.read(0, 512)
    print("First 16 bytes (Hex):", binascii.hexlify(mbr_data[:16], sep=' ').decode())
    print("MBR Signature (510-512):", binascii.hexlify(mbr_data[510:512], sep=' ').decode())
    
    # Try to detect Volume Info
    try:
        vs = pytsk3.Volume_Info(img)
        print(f"Volume Type: {vs.info.vstype}")
        for part in vs:
            print(f"Partition: {part.desc.decode()} | Start: {part.start} | Len: {part.len}")
    except Exception as e:
        print(f"Volume_Info failed: {e}")

    # Try to detect FS Info at various common offsets
    # 0, 63*512, 2048*512
    offsets = [0, 63*512, 2048*512, 4096*512]
    for offset in offsets:
        try:
            fs = pytsk3.FS_Info(img, offset=offset)
            print(f"FS FOUND at offset {offset}: Type: {fs.info.ftype}")
        except:
            pass

except Exception as e:
    print(f"Critical Debug Error: {e}")
