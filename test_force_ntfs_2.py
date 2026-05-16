import pytsk3

image_path = "/tmp/raw_image/ewf1"
offset = 63 * 512

try:
    img = pytsk3.Img_Info(image_path)
    print("Attempting to force NTFS type at offset 32256...")
    # In some pytsk3 versions it might be 'type' or positional
    # Let's try positional or check the help
    fs = pytsk3.FS_Info(img, offset=offset) # Standard call
    print("Standard call worked (if this prints)")
except Exception as e:
    print(f"Standard call failed: {e}")
    try:
        print("Trying with type=pytsk3.TSK_FS_TYPE_NTFS...")
        fs = pytsk3.FS_Info(img, offset=offset, type=pytsk3.TSK_FS_TYPE_NTFS)
        print("Forced type worked!")
    except Exception as e2:
        print(f"Forced type failed: {e2}")
