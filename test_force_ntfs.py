import pytsk3

image_path = "/tmp/raw_image/ewf1"
offset = 63 * 512

try:
    img = pytsk3.Img_Info(image_path)
    print("Attempting to force NTFS type at offset 32256...")
    fs = pytsk3.FS_Info(img, offset=offset, fstype=pytsk3.TSK_FS_TYPE_NTFS)
    print(f"SUCCESS! Forced NTFS open. Root dir inode: {fs.info.root_inum}")
except Exception as e:
    print(f"Forced open failed: {e}")
